OCAMLMAKEFILE = OCamlMakefile

SOURCES = src/utils.ml src/bgp.ml src/bmp.ml src/socket_reader.ml src/kafka_reader.ml src/main.ml
RESULT  = bmp2txt
PACKS = ppx_deriving.std ppx_deriving_yojson ppx_deriving_yojson.runtime hex ipaddr lwt lwt.unix kafka kafka.lwt yojson
THREADS = yes

all: debug-code
docker: all
	cp $(RESULT) docker/
	docker build -t bmp2txt docker/

include $(OCAMLMAKEFILE)