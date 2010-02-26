#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "pe.h"
#include "../aout-tool/a.out.h"

#define OFFSET(a, b) (((char *)(&a->b)) - ((char *)a))
#define INFO(a, b, c, d, e) printf("%08x: "c"%*.s%s\n", a + OFFSET(b, e), b->e, 9 - d, "", #e)

struct aout
{
	struct exec header;
	int textvad, textpos, textlen, datavad, datapos, datalen, rdatavad, rdatapos, rdatalen;
};

void init_aout(struct aout *a)
{
	memset(a, 0, sizeof(*a));
	a->header.a_magic[0] = A_MAGIC0;
	a->header.a_magic[1] = A_MAGIC1;
	a->header.a_flags = A_NSYM;
	a->header.a_cpu = A_I80386;
	a->header.a_hdrlen = sizeof(a->header);
	a->header.a_total = 0x500000;
}

int align16(int v)
{
	return (v + 15) / 16 * 16;
}

void print_pe_header(const char *buf, int len)
{
	int ad, i;
	PIMAGE_FILE_HEADER ph1;
	PIMAGE_OPTIONAL_HEADER32 ph2;
	PIMAGE_SECTION_HEADER sh;
	
	if (len < 0x40)
	{
		printf("FILE IS TOO SHORT: %d < %d\n", len, 0x40);
		return;
	}
	
	printf("%08x: %02x %02x    signature\n", 0, buf[0], buf[1]);
	if (buf[0] != 'M' || buf[1] != 'Z')
	{
		printf("BAD SIGNATURE: %02x %02x (must be %02x %02x)\n",
			buf[0], buf[1], 'M', 'Z');
		return;
	}
	
	ad = *(int *)&buf[0x3c];
	if (ad < 0 || ad + 4 + sizeof(*ph1) + sizeof(*ph2) > len)
	{
		printf("FILE IS TOO SHORT: %08x < %08x\n", len, ad);
		return;
	}
	
	printf("%08x: %02x %02x    PE signature\n", ad, buf[ad], buf[ad + 1]);
	if (buf[ad] != 'P' || buf[ad + 1] != 'E')
	{
		printf("BAD SIGNATURE: %02x %02x (must be %02x %02x)\n",
			buf[ad], buf[ad + 1], 'P', 'E');
		return;
	}
	ad += 4;
	
	ph1 = (PIMAGE_FILE_HEADER)&buf[ad];
	INFO(ad, ph1, "%04x", 4, Machine);
	INFO(ad, ph1, "%04x", 4, NumberOfSections);
	INFO(ad, ph1, "%08x", 8, TimeDateStamp);
	INFO(ad, ph1, "%08x", 8, PointerToSymbolTable);
	INFO(ad, ph1, "%08x", 8, NumberOfSymbols);
	INFO(ad, ph1, "%04x", 4, SizeOfOptionalHeader);
	INFO(ad, ph1, "%04x", 4, Characteristics);
	ad += sizeof(*ph1);
	
	ph2 = (PIMAGE_OPTIONAL_HEADER32)&buf[ad];
	INFO(ad, ph2, "%04x", 4, Magic);
	INFO(ad, ph2, "%02x", 2, MajorLinkerVersion);
	INFO(ad, ph2, "%02x", 2, MinorLinkerVersion);
	INFO(ad, ph2, "%08x", 8, SizeOfCode);
	INFO(ad, ph2, "%08x", 8, SizeOfInitializedData);
	INFO(ad, ph2, "%08x", 8, SizeOfUninitializedData);
	INFO(ad, ph2, "%08x", 8, AddressOfEntryPoint);
	INFO(ad, ph2, "%08x", 8, BaseOfCode);
	INFO(ad, ph2, "%08x", 8, BaseOfData);
	INFO(ad, ph2, "%08x", 8, ImageBase);
	INFO(ad, ph2, "%08x", 8, SectionAlignment);
	INFO(ad, ph2, "%08x", 8, FileAlignment);
	INFO(ad, ph2, "%04x", 4, MajorOperatingSystemVersion);
	INFO(ad, ph2, "%04x", 4, MinorOperatingSystemVersion);
	INFO(ad, ph2, "%04x", 4, MajorImageVersion);
	INFO(ad, ph2, "%04x", 4, MinorImageVersion);
	INFO(ad, ph2, "%04x", 4, MajorSubsystemVersion);
	INFO(ad, ph2, "%04x", 4, MinorSubsystemVersion);
	INFO(ad, ph2, "%08x", 8, Win32VersionValue);
	INFO(ad, ph2, "%08x", 8, SizeOfImage);
	INFO(ad, ph2, "%08x", 8, SizeOfHeaders);
	INFO(ad, ph2, "%08x", 8, CheckSum);
	INFO(ad, ph2, "%04x", 4, Subsystem);
	INFO(ad, ph2, "%04x", 4, DllCharacteristics);
	INFO(ad, ph2, "%08x", 8, SizeOfStackReserve);
	INFO(ad, ph2, "%08x", 8, SizeOfStackCommit);
	INFO(ad, ph2, "%08x", 8, SizeOfHeapReserve);
	INFO(ad, ph2, "%08x", 8, SizeOfHeapCommit);
	INFO(ad, ph2, "%08x", 8, LoaderFlags);
	INFO(ad, ph2, "%08x", 8, NumberOfRvaAndSizes);
	ad += sizeof(*ph2);
	
	for (i = 0; i < ph1->NumberOfSections; i++)
	{
		char name[9];
		sh = (PIMAGE_SECTION_HEADER)&buf[ad];
		strncpy(name, sh->Name, 8);
		printf("%08x: %-8s Name\n", ad, name);
		INFO(ad, sh, "%08x", 8, VirtualSize);
		INFO(ad, sh, "%08x", 8, VirtualAddress);
		INFO(ad, sh, "%08x", 8, SizeOfRawData);
		INFO(ad, sh, "%08x", 8, PointerToRawData);
		INFO(ad, sh, "%08x", 8, PointerToRelocations);
		INFO(ad, sh, "%08x", 8, PointerToLinenumbers);
		INFO(ad, sh, "%04x", 4, NumberOfRelocations);
		INFO(ad, sh, "%04x", 4, NumberOfLinenumbers);
		INFO(ad, sh, "%08x", 8, Characteristics);
		ad += sizeof(*sh);
	}
}

void parse_pe(struct aout *a, const char *buf, int len)
{
	int ad, i;
	PIMAGE_FILE_HEADER ph1;
	PIMAGE_OPTIONAL_HEADER32 ph2;
	PIMAGE_SECTION_HEADER sh;
	
	if (len < 0x40)
	{
		printf("FILE IS TOO SHORT: %d < %d\n", len, 0x40);
		return;
	}
	
	if (buf[0] != 'M' || buf[1] != 'Z')
	{
		printf("%08x: BAD SIGNATURE: %02x %02x (must be %02x %02x)\n",
			0, buf[0], buf[1], 'M', 'Z');
		return;
	}
	
	ad = *(int *)&buf[0x3c];
	if (ad < 0 || ad + 4 + sizeof(*ph1) + sizeof(*ph2) > len)
	{
		printf("FILE IS TOO SHORT: %08x < %08x\n", len, ad);
		return;
	}
	
	if (buf[ad] != 'P' || buf[ad + 1] != 'E')
	{
		printf("%08x: BAD SIGNATURE: %02x %02x (must be %02x %02x)\n",
			ad, buf[ad], buf[ad + 1], 'P', 'E');
		return;
	}
	ad += 4;
	
	ph1 = (PIMAGE_FILE_HEADER)&buf[ad];
	ad += sizeof(*ph1);
	
	ph2 = (PIMAGE_OPTIONAL_HEADER32)&buf[ad];
	ad += sizeof(*ph2);
	
	for (i = 0; i < ph1->NumberOfSections; i++)
	{
		char name[9];
		sh = (PIMAGE_SECTION_HEADER)&buf[ad];
		strncpy(name, sh->Name, 8);
		if (strcmp(name, ".text") == 0)
		{
			if (sh->VirtualAddress > 0x1000)
			{
				printf(".TEXT IS TOO FAR: %08x > 00001000\n", sh->VirtualAddress);
				return;
			}
			a->textvad = sh->VirtualAddress;
			a->textpos = sh->PointerToRawData;
			a->textlen = sh->VirtualSize;
			a->header.a_entry = ph2->AddressOfEntryPoint;
			a->header.a_text = a->textvad + align16(a->textlen);
		}
		else if (strcmp(name, ".data") == 0)
		{
			a->datavad = sh->VirtualAddress;
			a->datapos = sh->PointerToRawData;
			a->datalen = sh->VirtualSize;
			a->header.a_text = a->datavad;
			a->header.a_data = align16(a->datalen);
		}
		else if (strcmp(name, ".rdata") == 0)
		{
			a->rdatavad = sh->VirtualAddress;
			a->rdatapos = sh->PointerToRawData;
			a->rdatalen = sh->VirtualSize;
			if (a->datalen == 0)
			{
				a->header.a_text = a->rdatavad;
				a->header.a_data = align16(a->rdatalen);
			}
			else
				a->header.a_data = align16((a->rdatavad - a->datavad) + a->rdatalen);
		}
		else if (strcmp(name, ".bss") == 0)
		{
			a->header.a_bss = align16(sh->VirtualSize);
			if (a->datalen == 0 && a->rdatalen == 0)
				a->header.a_text = sh->VirtualAddress;
			else if (a->datalen == 0)
				a->header.a_data = sh->VirtualAddress - a->rdatavad;
			else
				a->header.a_data = sh->VirtualAddress - a->datavad;
		}
#if 0
		else if (strcmp(name, ".idata") == 0)
		{
			printf("CAN NOT IMPORT DLL!\n");
			a->header.a_text = 0;
			return;
		}
#endif
		ad += sizeof(*sh);
	}
	a->header.a_total += A_SYMPOS(a->header) - a->header.a_hdrlen;
}

void write_zero(FILE *f, int count)
{
	void *buf;
	if (count == 0) return;
	buf = calloc(count, 1);
	fwrite(buf, count, 1, f);
	free(buf);
}

void write_aout(struct aout *a, const char *buf, int len, const char *src)
{
	char *file, *p;
	FILE *f;
	
	if (a->textlen == 0) return;
	
	p = strrchr(src, '.');
	if (p == NULL)
	{
		printf("INVALID FILE NAME: %s\n", src);
		return;
	}
	
	file = strdup(src);
	*strrchr(file, '.') = '\0';
	printf("convert PE to a.out: %s => %s\n", src, file);
	
	f = fopen(file, "wb");
	if (f == NULL)
		printf("CAN NOT WRITE\n");
	else
	{
		int entry = a->header.a_entry;
		if (a->textvad > 10) a->header.a_entry = 0;
		fwrite(&a->header, sizeof(a->header), 1, f);
		if (a->textvad > 10)
		{
			char jmp[10];
			jmp[0] = 0xb8;
			*(int *)&jmp[1] = a->header.a_text + a->header.a_data + a->header.a_bss;
			jmp[5] = 0xe9;
			*(int *)&jmp[6] = entry - 10;
			fwrite(jmp, 10, 1, f);
			write_zero(f, a->textvad - 10);
		}
		fwrite(&buf[a->textpos], a->textlen, 1, f);
		write_zero(f, a->header.a_text - a->textlen - a->textvad);
		if (a->datalen > 0)
		{
			fwrite(&buf[a->datapos], a->datalen, 1, f);
			if (a->rdatalen == 0)
				write_zero(f, a->header.a_data - a->datalen);
			else
				write_zero(f, (a->rdatavad - a->datavad) - a->datalen);
		}
		if (a->rdatalen > 0)
		{
			fwrite(&buf[a->rdatapos], a->rdatalen, 1, f);
			if (a->datalen == 0)
				write_zero(f, a->header.a_data - a->rdatalen);
			else
				write_zero(f, a->header.a_data - a->rdatalen - (a->rdatavad - a->datavad));
		}
		fclose(f);
#ifndef WIN32
		chmod(file, 0755);
#endif
	}
	
	free(file);
}

void convert_pe(const char *file, int parse)
{
	FILE *f;
	struct stat st;
	char *buf;
	struct aout a;
	
	f = fopen(file, "rb");
	if (f == NULL)
	{
		printf("CAN NOT OPEN\n");
		return;
	}
	
	fstat(fileno(f), &st);
	buf = (char *)calloc(1, st.st_size + 1);
	fread(buf, 1, st.st_size, f);
	fclose(f);
	
	if (parse)
		print_pe_header(buf, st.st_size);
	else
	{
		init_aout(&a);
		parse_pe(&a, buf, st.st_size);
		write_aout(&a, buf, st.st_size, file);
	}
	free(buf);
}

int main(int argc, char *argv[])
{
	int i, parse = 0;
	if (argc <= 1)
	{
		fprintf(stderr, "usage: %s [-p] pe.exe [...]\n", argv[0]);
		return 1;
	}
	for (i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "-p") == 0)
			parse = 1;
		else
		{
			if (parse)
			{
				if (i > 1) printf("\n");
				if (argc > 2) printf("==== %s\n", argv[i]);
			}
			convert_pe(argv[i], parse);
		}
	}
	return 0;
}
