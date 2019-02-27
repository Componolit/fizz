build:
	mkdir -p generated
	rflx generate specs/*.rflx generated
	gprbuild -Pgreentls

clean:
	gprclean -Pgreentls
	rm -rf generated lib obj


