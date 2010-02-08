TARGET=pe2aout

$(TARGET): main.c pe.h a.out.h
	gcc -o $@ -s main.c

test: $(TARGET) test.exe
	./$(TARGET) test.exe

test.exe: test.c
	i686-mingw32-gcc -o $@ -masm=intel -s -Ttext=0 -Wl,--image-base=0 -Wl,--section-alignment=0x200 -nostdinc -nostdlib test.c

install: $(TARGET)
	cp $(TARGET) /usr/local/bin

clean:
	rm -f $(TARGET) test.exe test *core
