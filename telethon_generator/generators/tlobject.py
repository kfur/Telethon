import functools
import os
import re
import shutil
import struct
from collections import defaultdict
from zlib import crc32

from ..sourcebuilder import SourceBuilder
from ..utils import snake_to_camel_case

AUTO_GEN_NOTICE = \
    '"""File generated by TLObjects\' generator. All changes will be ERASED"""'


AUTO_CASTS = {
    'InputPeer':
        'utils.get_input_peer(await client.get_input_entity({}))',
    'InputChannel':
        'utils.get_input_channel(await client.get_input_entity({}))',
    'InputUser':
        'utils.get_input_user(await client.get_input_entity({}))',

    'InputDialogPeer': 'await client._get_input_dialog({})',
    'InputNotifyPeer': 'await client._get_input_notify({})',
    'InputMedia': 'utils.get_input_media({})',
    'InputPhoto': 'utils.get_input_photo({})',
    'InputMessage': 'utils.get_input_message({})',
    'InputDocument': 'utils.get_input_document({})',
    'InputChatPhoto': 'utils.get_input_chat_photo({})',
    'InputGroupCall': 'utils.get_input_group_call({})',
}

NAMED_AUTO_CASTS = {
    ('chat_id', 'int'): 'await client.get_peer_id({}, add_mark=False)'
}

# Secret chats have a chat_id which may be negative.
# With the named auto-cast above, we would break it.
# However there are plenty of other legit requests
# with `chat_id:int` where it is useful.
#
# NOTE: This works because the auto-cast is not recursive.
#       There are plenty of types that would break if we
#       did recurse into them to resolve them.
NAMED_BLACKLIST = {
    'messages.discardEncryption'
}

BASE_TYPES = ('string', 'bytes', 'int', 'long', 'int128',
              'int256', 'double', 'Bool', 'true', 'date')


def _write_modules(
        out_dir, depth, kind, namespace_tlobjects, type_constructors):
    # namespace_tlobjects: {'namespace', [TLObject]}
    out_dir.mkdir(parents=True, exist_ok=True)
    for ns, tlobjects in namespace_tlobjects.items():
        file = out_dir / '{}.py'.format(ns or '__init__')
        with file.open('w') as f, SourceBuilder(f) as builder:
            builder.writeln(AUTO_GEN_NOTICE)

            builder.writeln('from {}.tl.tlobject import TLObject', '.' * depth)
            if kind != 'TLObject':
                builder.writeln(
                    'from {}.tl.tlobject import {}', '.' * depth, kind)

            builder.writeln('from typing import Optional, List, '
                            'Union, TYPE_CHECKING')

            # Add the relative imports to the namespaces,
            # unless we already are in a namespace.
            if not ns:
                builder.writeln('from . import {}', ', '.join(sorted(
                    x for x in namespace_tlobjects.keys() if x
                )))

            # Import 'os' for those needing access to 'os.urandom()'
            # Currently only 'random_id' needs 'os' to be imported,
            # for all those TLObjects with arg.can_be_inferred.
            builder.writeln('import os')

            # Import struct for the .__bytes__(self) serialization
            builder.writeln('import struct')

            # Import datetime for type hinting
            builder.writeln('from datetime import datetime')

            tlobjects.sort(key=lambda x: x.name)

            type_names = set()
            type_defs = []

            # Find all the types in this file and generate type definitions
            # based on the types. The type definitions are written to the
            # file at the end.
            for t in tlobjects:
                if not t.is_function:
                    type_name = t.result
                    if '.' in type_name:
                        type_name = type_name[type_name.rindex('.'):]
                    if type_name in type_names:
                        continue
                    type_names.add(type_name)
                    constructors = type_constructors[type_name]
                    if not constructors:
                        pass
                    elif len(constructors) == 1:
                        type_defs.append('Type{} = {}'.format(
                            type_name, constructors[0].class_name))
                    else:
                        type_defs.append('Type{} = Union[{}]'.format(
                            type_name, ','.join(c.class_name
                                                for c in constructors)))

            imports = {}
            primitives = {'int', 'long', 'int128', 'int256', 'double',
                          'string', 'date', 'bytes', 'Bool', 'true'}
            # Find all the types in other files that are used in this file
            # and generate the information required to import those types.
            for t in tlobjects:
                for arg in t.args:
                    name = arg.type
                    if not name or name in primitives:
                        continue

                    import_space = '{}.tl.types'.format('.' * depth)
                    if '.' in name:
                        namespace = name.split('.')[0]
                        name = name.split('.')[1]
                        import_space += '.{}'.format(namespace)

                    if name not in type_names:
                        type_names.add(name)
                        if name == 'date':
                            imports['datetime'] = ['datetime']
                            continue
                        elif import_space not in imports:
                            imports[import_space] = set()
                        imports[import_space].add('Type{}'.format(name))

            # Add imports required for type checking
            if imports:
                builder.writeln('if TYPE_CHECKING:')
                for namespace, names in imports.items():
                    builder.writeln('from {} import {}',
                                    namespace, ', '.join(sorted(names)))

                builder.end_block()

            # Generate the class for every TLObject
            for t in tlobjects:
                _write_source_code(t, kind, builder, type_constructors)
                builder.current_indent = 0

            # Write the type definitions generated earlier.
            builder.writeln()
            for line in type_defs:
                builder.writeln(line)


def _write_source_code(tlobject, kind, builder, type_constructors):
    """
    Writes the source code corresponding to the given TLObject
    by making use of the ``builder`` `SourceBuilder`.

    Additional information such as file path depth and
    the ``Type: [Constructors]`` must be given for proper
    importing and documentation strings.
    """
    _write_class_init(tlobject, kind, type_constructors, builder)
    _write_resolve(tlobject, builder)
    _write_to_dict(tlobject, builder)
    _write_to_bytes(tlobject, builder)
    _write_from_reader(tlobject, builder)
    _write_read_result(tlobject, builder)


def _write_class_init(tlobject, kind, type_constructors, builder):
    builder.writeln()
    builder.writeln()
    builder.writeln('class {}({}):', tlobject.class_name, kind)

    # Class-level variable to store its Telegram's constructor ID
    builder.writeln('CONSTRUCTOR_ID = {:#x}', tlobject.id)
    builder.writeln('SUBCLASS_OF_ID = {:#x}',
                    crc32(tlobject.result.encode('ascii')))
    builder.writeln()

    slots_args = [f'\'{a.name}\',' for a in tlobject.real_args]
    if slots_args:
        builder.writeln('__slots__ = ' + " ".join(slots_args))
    else:
        builder.writeln('__slots__ = ()')
    builder.writeln()

    # Convert the args to string parameters, flags having =None
    args = ['{}: {}{}'.format(
        a.name, a.type_hint(), '=None' if a.is_flag or a.can_be_inferred else '')
        for a in tlobject.real_args
    ]

    # Write the __init__ function if it has any argument
    if not tlobject.real_args:
        return

    if any(a.name in __builtins__ for a in tlobject.real_args):
        builder.writeln('# noinspection PyShadowingBuiltins')

    builder.writeln("def __init__({}):", ', '.join(['self'] + args))
    builder.writeln('"""')
    if tlobject.is_function:
        builder.write(':returns {}: ', tlobject.result)
    else:
        builder.write('Constructor for {}: ', tlobject.result)

    constructors = type_constructors[tlobject.result]
    if not constructors:
        builder.writeln('This type has no constructors.')
    elif len(constructors) == 1:
        builder.writeln('Instance of {}.',
                        constructors[0].class_name)
    else:
        builder.writeln('Instance of either {}.', ', '.join(
            c.class_name for c in constructors))

    builder.writeln('"""')

    # Set the arguments
    for arg in tlobject.real_args:
        if not arg.can_be_inferred:
            builder.writeln('self.{0} = {0}', arg.name)

        # Currently the only argument that can be
        # inferred are those called 'random_id'
        elif arg.name == 'random_id':
            # Endianness doesn't really matter, and 'big' is shorter
            code = "int.from_bytes(os.urandom({}), 'big', signed=True)" \
                .format(8 if arg.type == 'long' else 4)

            if arg.is_vector:
                # Currently for the case of "messages.forwardMessages"
                # Ensure we can infer the length from id:Vector<>
                if not next(a for a in tlobject.real_args
                            if a.name == 'id').is_vector:
                    raise ValueError(
                        'Cannot infer list of random ids for ', tlobject
                    )
                code = '[{} for _ in range(len(id))]'.format(code)

            builder.writeln(
                "self.random_id = random_id if random_id "
                "is not None else {}", code
            )
        else:
            raise ValueError('Cannot infer a value for ', arg)

    builder.end_block()


def _write_resolve(tlobject, builder):
    if tlobject.is_function and any(
            (arg.type in AUTO_CASTS
             or ((arg.name, arg.type) in NAMED_AUTO_CASTS
                 and tlobject.fullname not in NAMED_BLACKLIST))
            for arg in tlobject.real_args
    ):
        builder.writeln('async def resolve(self, client, utils):')
        for arg in tlobject.real_args:
            ac = AUTO_CASTS.get(arg.type)
            if not ac:
                ac = NAMED_AUTO_CASTS.get((arg.name, arg.type))
                if not ac:
                    continue

            if arg.is_flag:
                builder.writeln('if self.{}:', arg.name)

            if arg.is_vector:
                builder.writeln('_tmp = []')
                builder.writeln('for _x in self.{0}:', arg.name)
                builder.writeln('_tmp.append({})', ac.format('_x'))
                builder.end_block()
                builder.writeln('self.{} = _tmp', arg.name)
            else:
                builder.writeln('self.{} = {}', arg.name,
                              ac.format('self.' + arg.name))

            if arg.is_flag:
                builder.end_block()
        builder.end_block()


def _write_to_dict(tlobject, builder):
    builder.writeln('def to_dict(self):')
    builder.writeln('return {')
    builder.current_indent += 1

    builder.write("'_': '{}'", tlobject.class_name)
    for arg in tlobject.real_args:
        builder.writeln(',')
        builder.write("'{}': ", arg.name)
        if arg.type in BASE_TYPES:
            if arg.is_vector:
                builder.write('[] if self.{0} is None else self.{0}[:]',
                              arg.name)
            else:
                builder.write('self.{}', arg.name)
        else:
            if arg.is_vector:
                builder.write(
                    '[] if self.{0} is None else [x.to_dict() '
                    'if isinstance(x, TLObject) else x for x in self.{0}]',
                    arg.name
                )
            else:
                builder.write(
                    'self.{0}.to_dict() '
                    'if isinstance(self.{0}, TLObject) else self.{0}',
                    arg.name
                )

    builder.writeln()
    builder.current_indent -= 1
    builder.writeln("}")

    builder.end_block()


def _write_to_bytes(tlobject, builder):
    builder.writeln('def _bytes(self):')

    # Some objects require more than one flag parameter to be set
    # at the same time. In this case, add an assertion.
    repeated_args = defaultdict(list)
    for arg in tlobject.args:
        if arg.is_flag:
            repeated_args[arg.flag_index].append(arg)

    for ra in repeated_args.values():
        if len(ra) > 1:
            cnd1 = ('(self.{0} or self.{0} is not None)'
                    .format(a.name) for a in ra)
            cnd2 = ('(self.{0} is None or self.{0} is False)'
                    .format(a.name) for a in ra)
            builder.writeln(
                "assert ({}) or ({}), '{} parameters must all "
                "be False-y (like None) or all me True-y'",
                ' and '.join(cnd1), ' and '.join(cnd2),
                ', '.join(a.name for a in ra)
            )

    builder.writeln("return b''.join((")
    builder.current_indent += 1

    # First constructor code, we already know its bytes
    builder.writeln('{},', repr(struct.pack('<I', tlobject.id)))

    for arg in tlobject.args:
        if _write_arg_to_bytes(builder, arg, tlobject):
            builder.writeln(',')

    builder.current_indent -= 1
    builder.writeln('))')
    builder.end_block()


def _write_from_reader(tlobject, builder):
    builder.writeln('@classmethod')
    builder.writeln('def from_reader(cls, reader):')
    for arg in tlobject.args:
        _write_arg_read_code(builder, arg, tlobject, name='_' + arg.name)

    builder.writeln('return cls({})', ', '.join(
        '{0}=_{0}'.format(a.name) for a in tlobject.real_args))


def _write_read_result(tlobject, builder):
    # Only requests can have a different response that's not their
    # serialized body, that is, we'll be setting their .result.
    #
    # The default behaviour is reading a TLObject too, so no need
    # to override it unless necessary.
    if not tlobject.is_function:
        return

    # https://core.telegram.org/mtproto/serialize#boxed-and-bare-types
    # TL;DR; boxed types start with uppercase always, so we can use
    # this to check whether everything in it is boxed or not.
    #
    # Currently only un-boxed responses are Vector<int>/Vector<long>.
    # If this weren't the case, we should check upper case after
    # max(index('<'), index('.')) (and if it is, it's boxed, so return).
    m = re.match(r'Vector<(int|long)>', tlobject.result)
    if not m:
        return

    builder.end_block()
    builder.writeln('@staticmethod')
    builder.writeln('def read_result(reader):')
    builder.writeln('reader.read_int()  # Vector ID')
    builder.writeln('return [reader.read_{}() '
                    'for _ in range(reader.read_int())]', m.group(1))


def _write_arg_to_bytes(builder, arg, tlobject, name=None):
    """
    Writes the .__bytes__() code for the given argument
    :param builder: The source code builder
    :param arg: The argument to write
    :param tlobject: The parent TLObject
    :param name: The name of the argument. Defaults to "self.argname"
                 This argument is an option because it's required when
                 writing Vectors<>
    """
    if arg.generic_definition:
        return  # Do nothing, this only specifies a later type

    if name is None:
        name = 'self.{}'.format(arg.name)

    # The argument may be a flag, only write if it's not None AND
    # if it's not a True type.
    # True types are not actually sent, but instead only used to
    # determine the flags.
    if arg.is_flag:
        if arg.type == 'true':
            return  # Exit, since True type is never written
        elif arg.is_vector:
            # Vector flags are special since they consist of 3 values,
            # so we need an extra join here. Note that empty vector flags
            # should NOT be sent either!
            builder.write("b'' if {0} is None or {0} is False "
                          "else b''.join((", name)
        elif 'Bool' == arg.type:
            # `False` is a valid value for this type, so only check for `None`.
            builder.write("b'' if {0} is None else (", name)
        else:
            builder.write("b'' if {0} is None or {0} is False "
                          "else (", name)

    if arg.is_vector:
        if arg.use_vector_id:
            # vector code, unsigned 0x1cb5c415 as little endian
            builder.write(r"b'\x15\xc4\xb5\x1c',")

        builder.write("struct.pack('<i', len({})),", name)

        # Cannot unpack the values for the outer tuple through *[(
        # since that's a Python >3.5 feature, so add another join.
        builder.write("b''.join(")

        # Temporary disable .is_vector, not to enter this if again
        # Also disable .is_flag since it's not needed per element
        old_flag = arg.is_flag
        arg.is_vector = arg.is_flag = False
        _write_arg_to_bytes(builder, arg, tlobject, name='x')
        arg.is_vector = True
        arg.is_flag = old_flag

        builder.write(' for x in {})', name)

    elif arg.flag_indicator:
        # Calculate the flags with those items which are not None
        if not any(f.is_flag for f in tlobject.args):
            # There's a flag indicator, but no flag arguments so it's 0
            builder.write(r"b'\0\0\0\0'")
        else:
            def fmt_flag(flag):
                if flag.type == 'Bool':
                    fmt = '(0 if {0} is None else {1})'
                else:
                    fmt = '(0 if {0} is None or {0} is False else {1})'
                return fmt.format('self.{}'.format(flag.name), 1 << flag.flag_index)

            builder.write("struct.pack('<I', ")
            builder.write(
                ' | '.join(fmt_flag(flag) for flag in tlobject.args if flag.is_flag)
            )
            builder.write(')')

    elif 'int' == arg.type:
        # User IDs are becoming larger than 2³¹ - 1, which would translate
        # into reading a negative ID, which we would treat as a chat. So
        # special case them to read unsigned. See https://t.me/BotNews/57.
        if arg.name == 'user_id' or (arg.name == 'id' and tlobject.result == 'User'):
            builder.write("struct.pack('<I', {})", name)
        else:
            # struct.pack is around 4 times faster than int.to_bytes
            builder.write("struct.pack('<i', {})", name)

    elif 'long' == arg.type:
        builder.write("struct.pack('<q', {})", name)

    elif 'int128' == arg.type:
        builder.write("{}.to_bytes(16, 'little', signed=True)", name)

    elif 'int256' == arg.type:
        builder.write("{}.to_bytes(32, 'little', signed=True)", name)

    elif 'double' == arg.type:
        builder.write("struct.pack('<d', {})", name)

    elif 'string' == arg.type:
        builder.write('self.serialize_bytes({})', name)

    elif 'Bool' == arg.type:
        # 0x997275b5 if boolean else 0xbc799737
        builder.write(r"b'\xb5ur\x99' if {} else b'7\x97y\xbc'", name)

    elif 'true' == arg.type:
        pass  # These are actually NOT written! Only used for flags

    elif 'bytes' == arg.type:
        builder.write('self.serialize_bytes({})', name)

    elif 'date' == arg.type:  # Custom format
        builder.write('self.serialize_datetime({})', name)

    else:
        # Else it may be a custom type
        builder.write('{}._bytes()', name)

        # If the type is not boxed (i.e. starts with lowercase) we should
        # not serialize the constructor ID (so remove its first 4 bytes).
        boxed = arg.type[arg.type.find('.') + 1].isupper()
        if not boxed:
            builder.write('[4:]')

    if arg.is_flag:
        builder.write(')')
        if arg.is_vector:
            builder.write(')')  # We were using a tuple

    return True  # Something was written


def _write_arg_read_code(builder, arg, tlobject, name):
    """
    Writes the read code for the given argument, setting the
    arg.name variable to its read value.

    :param builder: The source code builder
    :param arg: The argument to write
    :param tlobject: The parent TLObject
    :param name: The name of the argument. Defaults to "self.argname"
                 This argument is an option because it's required when
                 writing Vectors<>
    """

    if arg.generic_definition:
        return  # Do nothing, this only specifies a later type

    # The argument may be a flag, only write that flag was given!
    was_flag = False
    if arg.is_flag:
        # Treat 'true' flags as a special case, since they're true if
        # they're set, and nothing else needs to actually be read.
        if 'true' == arg.type:
            builder.writeln('{} = bool(flags & {})',
                            name, 1 << arg.flag_index)
            return

        was_flag = True
        builder.writeln('if flags & {}:', 1 << arg.flag_index)
        # Temporary disable .is_flag not to enter this if
        # again when calling the method recursively
        arg.is_flag = False

    if arg.is_vector:
        if arg.use_vector_id:
            # We have to read the vector's constructor ID
            builder.writeln("reader.read_int()")

        builder.writeln('{} = []', name)
        builder.writeln('for _ in range(reader.read_int()):')
        # Temporary disable .is_vector, not to enter this if again
        arg.is_vector = False
        _write_arg_read_code(builder, arg, tlobject, name='_x')
        builder.writeln('{}.append(_x)', name)
        arg.is_vector = True

    elif arg.flag_indicator:
        # Read the flags, which will indicate what items we should read next
        builder.writeln('flags = reader.read_int()')
        builder.writeln()

    elif 'int' == arg.type:
        # User IDs are becoming larger than 2³¹ - 1, which would translate
        # into reading a negative ID, which we would treat as a chat. So
        # special case them to read unsigned. See https://t.me/BotNews/57.
        if arg.name == 'user_id' or (arg.name == 'id' and tlobject.result == 'User'):
            builder.writeln('{} = reader.read_int(signed=False)', name)
        else:
            builder.writeln('{} = reader.read_int()', name)

    elif 'long' == arg.type:
        builder.writeln('{} = reader.read_long()', name)

    elif 'int128' == arg.type:
        builder.writeln('{} = reader.read_large_int(bits=128)', name)

    elif 'int256' == arg.type:
        builder.writeln('{} = reader.read_large_int(bits=256)', name)

    elif 'double' == arg.type:
        builder.writeln('{} = reader.read_double()', name)

    elif 'string' == arg.type:
        builder.writeln('{} = reader.tgread_string()', name)

    elif 'Bool' == arg.type:
        builder.writeln('{} = reader.tgread_bool()', name)

    elif 'true' == arg.type:
        # Arbitrary not-None value, don't actually read "true" flags
        builder.writeln('{} = True', name)

    elif 'bytes' == arg.type:
        builder.writeln('{} = reader.tgread_bytes()', name)

    elif 'date' == arg.type:  # Custom format
        builder.writeln('{} = reader.tgread_date()', name)

    else:
        # Else it may be a custom type
        if not arg.skip_constructor_id:
            builder.writeln('{} = reader.tgread_object()', name)
        else:
            # Import the correct type inline to avoid cyclic imports.
            # There may be better solutions so that we can just access
            # all the types before the files have been parsed, but I
            # don't know of any.
            sep_index = arg.type.find('.')
            if sep_index == -1:
                ns, t = '.', arg.type
            else:
                ns, t = '.' + arg.type[:sep_index], arg.type[sep_index+1:]
            class_name = snake_to_camel_case(t)

            # There would be no need to import the type if we're in the
            # file with the same namespace, but since it does no harm
            # and we don't have information about such thing in the
            # method we just ignore that case.
            builder.writeln('from {} import {}', ns, class_name)
            builder.writeln('{} = {}.from_reader(reader)',
                            name, class_name)

    # End vector and flag blocks if required (if we opened them before)
    if arg.is_vector:
        builder.end_block()

    if was_flag:
        builder.current_indent -= 1
        builder.writeln('else:')
        builder.writeln('{} = None', name)
        builder.current_indent -= 1
        # Restore .is_flag
        arg.is_flag = True


def _write_all_tlobjects(tlobjects, layer, builder):
    builder.writeln(AUTO_GEN_NOTICE)
    builder.writeln()

    builder.writeln('from . import types, functions')
    builder.writeln()

    # Create a constant variable to indicate which layer this is
    builder.writeln('LAYER = {}', layer)
    builder.writeln()

    # Then create the dictionary containing constructor_id: class
    builder.writeln('tlobjects = {')
    builder.current_indent += 1

    # Fill the dictionary (0x1a2b3c4f: tl.full.type.path.Class)
    for tlobject in tlobjects:
        builder.write('{:#010x}: ', tlobject.id)
        builder.write('functions' if tlobject.is_function else 'types')

        if tlobject.namespace:
            builder.write('.{}', tlobject.namespace)

        builder.writeln('.{},', tlobject.class_name)

    builder.current_indent -= 1
    builder.writeln('}')


def generate_tlobjects(tlobjects, layer, import_depth, output_dir):
    # Group everything by {namespace: [tlobjects]} to generate __init__.py
    namespace_functions = defaultdict(list)
    namespace_types = defaultdict(list)

    # Group {type: [constructors]} to generate the documentation
    type_constructors = defaultdict(list)
    for tlobject in tlobjects:
        if tlobject.is_function:
            namespace_functions[tlobject.namespace].append(tlobject)
        else:
            namespace_types[tlobject.namespace].append(tlobject)
            type_constructors[tlobject.result].append(tlobject)

    _write_modules(output_dir / 'functions', import_depth, 'TLRequest',
                   namespace_functions, type_constructors)
    _write_modules(output_dir / 'types', import_depth, 'TLObject',
                   namespace_types, type_constructors)

    filename = output_dir / 'alltlobjects.py'
    with filename.open('w') as file:
        with SourceBuilder(file) as builder:
            _write_all_tlobjects(tlobjects, layer, builder)


def clean_tlobjects(output_dir):
    for d in ('functions', 'types'):
        d = output_dir / d
        if d.is_dir():
            shutil.rmtree(str(d))

    tl = output_dir / 'alltlobjects.py'
    if tl.is_file():
        tl.unlink()
