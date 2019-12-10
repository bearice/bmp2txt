OCAMLMAKEFILE = OCamlMakefile

SOURCES = main.ml 
RESULT  = bmp2txt
PACKS = ppx_deriving.std hex bitstring bitstring.ppx
THREADS = yes

all: debug-code
include $(OCAMLMAKEFILE)