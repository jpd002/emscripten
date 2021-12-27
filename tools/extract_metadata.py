from . import webassembly
from .shared import exit_with_error
from .settings import settings


def is_wrapper_function(module, function):
  module.seek(function.offset)
  num_local_decls = module.readULEB()
  while num_local_decls:
    local_count = module.readULEB()  # noqa
    local_type = module.read_type()  # noqa
    num_local_decls -= 1
  end = function.offset + function.size
  while module.tell() != end:
    opcode = module.readByte()
    try:
      opcode = webassembly.OpCode(opcode)
    except ValueError as e:
      print(e)
      return False
    if opcode == webassembly.OpCode.CALL:
      callee = module.readULEB()  # noqa
    elif opcode in (webassembly.OpCode.LOCAL_GET, webassembly.OpCode.LOCAL_SET):
      local = module.readULEB()  # noqa
    elif opcode == webassembly.OpCode.RETURN:
      pass
    else:
      return False
  assert opcode == webassembly.OpCode.END
  return True


def get_const_expr_value(expr):
  assert len(expr) == 2
  assert expr[1][0] == webassembly.OpCode.END
  opcode, immediates = expr[0]
  if opcode in (webassembly.OpCode.I32_CONST, webassembly.OpCode.I64_CONST):
    assert len(immediates) == 1
    return immediates[0]
  elif opcode in (webassembly.OpCode.GLOBAL_GET,):
    return 0
  else:
    exit_with_error('unexpected opcode in const expr: ' + str(opcode))


def get_global_value(globl):
  return get_const_expr_value(globl.init)


def find_segment_with_address(module, address, size):
  segments = module.get_segments()
  active = [s for s in segments if s.init]

  for seg in active:
    offset = get_const_expr_value(seg.init)
    if offset is None:
      continue
    if offset == address:
      return (seg, 0)
    if address > offset and address < offset + seg.size:
      return (seg, address - offset)

  passive = [s for s in segments if not s.init]
  for seg in passive:
    if seg.size == size:
      return (seg, 0)


def get_asm_strings(module, globls, export_map, imported_globals):
  if '__start_em_asm' not in export_map or '__stop_em_asm' not in export_map:
    return {}

  start = export_map['__start_em_asm']
  end = export_map['__stop_em_asm']
  start_global = globls[start.index - imported_globals]
  end_global = globls[end.index - imported_globals]
  start_addr = get_global_value(start_global)
  end_addr = get_global_value(end_global)

  seg = find_segment_with_address(module, start_addr, end_addr - start_addr)
  if not seg:
    exit_with_error('unable to find segment starting at __start_em_asm: %s' % start_addr)
  seg, seg_offset = seg

  asm_strings = {}
  str_start = seg_offset
  data = module.readAt(seg.offset, seg.size)
  while str_start < seg.size:
    str_end = data.find(b'\0', str_start)
    asm_strings[str(start_addr + str_start)] = data[str_start:str_end].decode('utf-8')
    str_start = str_end + 1
  return asm_strings



def get_main_reads_params(module, export_map, imported_funcs):
  if settings.STANDALONE_WASM:
    return 1

  main = export_map.get('main')
  if main and main.kind == webassembly.ExternType.FUNC:
    functions = module.get_functions()
    main_func = functions[main.index - imported_funcs]
    if is_wrapper_function(module, main_func):
      return 0
    else:
      return 1

  return 0


def get_names_globals(globls, exports, imported_globals):
  named_globals = {}
  for export in exports:
    if export.kind == webassembly.ExternType.GLOBAL:
      if export.name in ('__start_em_asm', '__stop_em_asm'):
        continue
      g = globls[export.index - imported_globals]
      named_globals[export.name] = str(get_global_value(g))
  return named_globals


def extract_metadata(filename):
  module = webassembly.Module(filename)
  export_names = []
  declares = []
  invoke_funcs = []
  imported_funcs = 0
  imported_globals = 0
  global_imports = []
  exports = module.get_exports()
  imports = module.get_imports()
  globls = module.get_globals()
  for i in imports:
    if i.kind == webassembly.ExternType.FUNC:
      if i.field.startswith('invoke_'):
        invoke_funcs.append(i.field)
      else:
        declares.append(i.field)
      imported_funcs += 1
    elif i.kind == webassembly.ExternType.GLOBAL:
      imported_globals += 1
      global_imports.append(i.field)
  export_names = [e.name for e in exports if e.kind == webassembly.ExternType.FUNC]
  export_map = {e.name: e for e in exports}

  features = module.parse_features_section()
  features = ['--enable-' + f[1] for f in features if f[0] == '+']
  features = [f.replace('--enable-atomics', '--enable-threads') for f in features]

  # If main does not read its parameters, it will just be a stub that
  # calls __original_main (which has no parameters).
  metadata = {}
  metadata['asmConsts'] = get_asm_strings(module, globls, export_map, imported_globals)
  metadata['declares'] = declares
  metadata['emJsFuncs'] = {}
  metadata['exports'] = export_names
  metadata['features'] = features
  metadata['globalImports'] = global_imports
  metadata['invokeFuncs'] = invoke_funcs
  metadata['mainReadsParams'] = get_main_reads_params(module, export_map, imported_funcs)
  metadata['namedGlobals'] = get_names_globals(globls, exports, imported_globals)
  # print("Metadata parsed: " + pprint.pformat(metadata))
  return metadata
