p4c_image := ccasconeonf/p4c

mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
current_dir := $(patsubst %/,%,$(dir $(mkfile_path)))
src_dir := $(current_dir)/p4src
build_dir := $(current_dir)/build

docker_run := docker run --rm -v $(src_dir):$(src_dir) -v $(build_dir):$(build_dir)

.PHONY: build

build: build14 build16

build14: mkdir
	$(docker_run) -w $(src_dir) $(p4c_image) p4c-bm2-ss \
		--std p4-14 -o $(build_dir)/bmv2.json \
		--p4runtime-files $(build_dir)/p4info.txt \
		se.p4

build16: mkdir
	$(docker_run) -w $(src_dir) $(p4c_image) p4c-bm2-ss \
		--std p4-16 -o $(build_dir)/bmv2_16.json \
		--p4runtime-files $(build_dir)/p4info_16.txt \
		se16.p4

mkdir:
	mkdir -p $(build_dir)

clean:
	-rm -rf $(build_dir)