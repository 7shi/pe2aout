int m[] = { 0, 1/*EXIT*/, 42, 0, 0, 0, 0, 0, 0 };

void start()
{
	asm("mov eax, 0; mov ecx, 3; int 0x21" :: "b"(m));
}
