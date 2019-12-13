OCAMLMAKEFILE = OCamlMakefile

SOURCES = src/utils.ml src/bgp.ml src/bmp.ml src/main.ml
RESULT  = bmp2txt
PACKS = ppx_deriving.std hex bitstring bitstring.ppx ipaddr cstruct ppx_cstruct lwt lwt.unix kafka kafka.lwt
THREADS = yes

all: debug-code
include $(OCAMLMAKEFILE)