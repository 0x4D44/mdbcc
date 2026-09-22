/* Large-.text regression corpus for the dynamic PE section layout.
   Before the layout fix any program whose .text exceeded 4 KB produced
   an invalid PE (overlapping section RVAs) that Windows refused to
   load. This unit has several KB of .text (well over the old 4 KB
   ceiling) plus a printf import and a string literal emitted after
   it. It also declares a file-scope char* global initialised to a
   string literal and prints it via %s AFTER the large .text, so the
   differential/determinism oracles also cover the .data absolute
   pointer-to-string path in the dynamically-shifted-RVA regime. A
   char* + %s is byte-identical across cl/bcc32/mdbcc (no pointer- or
   int-size dependence). Strict C89; deterministic; no
   uninitialised reads; only int arithmetic bounded by %1000, so the
   result is identical on 32-bit (bcc32) and 64-bit (mdbcc). */
#include <stdio.h>
char *tag = "T:";
int g0(int x){ int a; a = x * 0 + 7; a = a % 1000; if (a < 0) a = -a; return a + 0; }
int g1(int x){ int a; a = x * 1 + 7; a = a % 1000; if (a < 0) a = -a; return a + 1; }
int g2(int x){ int a; a = x * 2 + 7; a = a % 1000; if (a < 0) a = -a; return a + 2; }
int g3(int x){ int a; a = x * 3 + 7; a = a % 1000; if (a < 0) a = -a; return a + 3; }
int g4(int x){ int a; a = x * 4 + 7; a = a % 1000; if (a < 0) a = -a; return a + 4; }
int g5(int x){ int a; a = x * 5 + 7; a = a % 1000; if (a < 0) a = -a; return a + 5; }
int g6(int x){ int a; a = x * 6 + 7; a = a % 1000; if (a < 0) a = -a; return a + 6; }
int g7(int x){ int a; a = x * 7 + 7; a = a % 1000; if (a < 0) a = -a; return a + 7; }
int g8(int x){ int a; a = x * 8 + 7; a = a % 1000; if (a < 0) a = -a; return a + 8; }
int g9(int x){ int a; a = x * 9 + 7; a = a % 1000; if (a < 0) a = -a; return a + 9; }
int g10(int x){ int a; a = x * 10 + 7; a = a % 1000; if (a < 0) a = -a; return a + 10; }
int g11(int x){ int a; a = x * 11 + 7; a = a % 1000; if (a < 0) a = -a; return a + 11; }
int g12(int x){ int a; a = x * 12 + 7; a = a % 1000; if (a < 0) a = -a; return a + 12; }
int g13(int x){ int a; a = x * 13 + 7; a = a % 1000; if (a < 0) a = -a; return a + 13; }
int g14(int x){ int a; a = x * 14 + 7; a = a % 1000; if (a < 0) a = -a; return a + 14; }
int g15(int x){ int a; a = x * 15 + 7; a = a % 1000; if (a < 0) a = -a; return a + 15; }
int g16(int x){ int a; a = x * 16 + 7; a = a % 1000; if (a < 0) a = -a; return a + 16; }
int g17(int x){ int a; a = x * 17 + 7; a = a % 1000; if (a < 0) a = -a; return a + 17; }
int g18(int x){ int a; a = x * 18 + 7; a = a % 1000; if (a < 0) a = -a; return a + 18; }
int g19(int x){ int a; a = x * 19 + 7; a = a % 1000; if (a < 0) a = -a; return a + 19; }
int g20(int x){ int a; a = x * 20 + 7; a = a % 1000; if (a < 0) a = -a; return a + 20; }
int g21(int x){ int a; a = x * 21 + 7; a = a % 1000; if (a < 0) a = -a; return a + 21; }
int g22(int x){ int a; a = x * 22 + 7; a = a % 1000; if (a < 0) a = -a; return a + 22; }
int g23(int x){ int a; a = x * 23 + 7; a = a % 1000; if (a < 0) a = -a; return a + 23; }
int g24(int x){ int a; a = x * 24 + 7; a = a % 1000; if (a < 0) a = -a; return a + 24; }
int g25(int x){ int a; a = x * 25 + 7; a = a % 1000; if (a < 0) a = -a; return a + 25; }
int g26(int x){ int a; a = x * 26 + 7; a = a % 1000; if (a < 0) a = -a; return a + 26; }
int g27(int x){ int a; a = x * 27 + 7; a = a % 1000; if (a < 0) a = -a; return a + 27; }
int g28(int x){ int a; a = x * 28 + 7; a = a % 1000; if (a < 0) a = -a; return a + 28; }
int g29(int x){ int a; a = x * 29 + 7; a = a % 1000; if (a < 0) a = -a; return a + 29; }
int g30(int x){ int a; a = x * 30 + 7; a = a % 1000; if (a < 0) a = -a; return a + 30; }
int g31(int x){ int a; a = x * 31 + 7; a = a % 1000; if (a < 0) a = -a; return a + 31; }
int g32(int x){ int a; a = x * 32 + 7; a = a % 1000; if (a < 0) a = -a; return a + 32; }
int g33(int x){ int a; a = x * 33 + 7; a = a % 1000; if (a < 0) a = -a; return a + 33; }
int g34(int x){ int a; a = x * 34 + 7; a = a % 1000; if (a < 0) a = -a; return a + 34; }
int g35(int x){ int a; a = x * 35 + 7; a = a % 1000; if (a < 0) a = -a; return a + 35; }
int g36(int x){ int a; a = x * 36 + 7; a = a % 1000; if (a < 0) a = -a; return a + 36; }
int g37(int x){ int a; a = x * 37 + 7; a = a % 1000; if (a < 0) a = -a; return a + 37; }
int g38(int x){ int a; a = x * 38 + 7; a = a % 1000; if (a < 0) a = -a; return a + 38; }
int g39(int x){ int a; a = x * 39 + 7; a = a % 1000; if (a < 0) a = -a; return a + 39; }
int g40(int x){ int a; a = x * 40 + 7; a = a % 1000; if (a < 0) a = -a; return a + 40; }
int g41(int x){ int a; a = x * 41 + 7; a = a % 1000; if (a < 0) a = -a; return a + 41; }
int g42(int x){ int a; a = x * 42 + 7; a = a % 1000; if (a < 0) a = -a; return a + 42; }
int g43(int x){ int a; a = x * 43 + 7; a = a % 1000; if (a < 0) a = -a; return a + 43; }
int g44(int x){ int a; a = x * 44 + 7; a = a % 1000; if (a < 0) a = -a; return a + 44; }
int g45(int x){ int a; a = x * 45 + 7; a = a % 1000; if (a < 0) a = -a; return a + 45; }
int g46(int x){ int a; a = x * 46 + 7; a = a % 1000; if (a < 0) a = -a; return a + 46; }
int g47(int x){ int a; a = x * 47 + 7; a = a % 1000; if (a < 0) a = -a; return a + 47; }
int g48(int x){ int a; a = x * 48 + 7; a = a % 1000; if (a < 0) a = -a; return a + 48; }
int g49(int x){ int a; a = x * 49 + 7; a = a % 1000; if (a < 0) a = -a; return a + 49; }
int g50(int x){ int a; a = x * 50 + 7; a = a % 1000; if (a < 0) a = -a; return a + 50; }
int g51(int x){ int a; a = x * 51 + 7; a = a % 1000; if (a < 0) a = -a; return a + 51; }
int g52(int x){ int a; a = x * 52 + 7; a = a % 1000; if (a < 0) a = -a; return a + 52; }
int g53(int x){ int a; a = x * 53 + 7; a = a % 1000; if (a < 0) a = -a; return a + 53; }
int g54(int x){ int a; a = x * 54 + 7; a = a % 1000; if (a < 0) a = -a; return a + 54; }
int g55(int x){ int a; a = x * 55 + 7; a = a % 1000; if (a < 0) a = -a; return a + 55; }
int g56(int x){ int a; a = x * 56 + 7; a = a % 1000; if (a < 0) a = -a; return a + 56; }
int g57(int x){ int a; a = x * 57 + 7; a = a % 1000; if (a < 0) a = -a; return a + 57; }
int g58(int x){ int a; a = x * 58 + 7; a = a % 1000; if (a < 0) a = -a; return a + 58; }
int g59(int x){ int a; a = x * 59 + 7; a = a % 1000; if (a < 0) a = -a; return a + 59; }
int g60(int x){ int a; a = x * 60 + 7; a = a % 1000; if (a < 0) a = -a; return a + 60; }
int g61(int x){ int a; a = x * 61 + 7; a = a % 1000; if (a < 0) a = -a; return a + 61; }
int g62(int x){ int a; a = x * 62 + 7; a = a % 1000; if (a < 0) a = -a; return a + 62; }
int g63(int x){ int a; a = x * 63 + 7; a = a % 1000; if (a < 0) a = -a; return a + 63; }
int main(void){
    int s;
    s = 0;
    s += g0(0);
    s += g1(1);
    s += g2(2);
    s += g3(3);
    s += g4(4);
    s += g5(5);
    s += g6(6);
    s += g7(7);
    s += g8(8);
    s += g9(9);
    s += g10(10);
    s += g11(11);
    s += g12(12);
    s += g13(13);
    s += g14(14);
    s += g15(15);
    s += g16(16);
    s += g17(17);
    s += g18(18);
    s += g19(19);
    s += g20(20);
    s += g21(21);
    s += g22(22);
    s += g23(23);
    s += g24(24);
    s += g25(25);
    s += g26(26);
    s += g27(27);
    s += g28(28);
    s += g29(29);
    s += g30(30);
    s += g31(31);
    s += g32(32);
    s += g33(33);
    s += g34(34);
    s += g35(35);
    s += g36(36);
    s += g37(37);
    s += g38(38);
    s += g39(39);
    s += g40(40);
    s += g41(41);
    s += g42(42);
    s += g43(43);
    s += g44(44);
    s += g45(45);
    s += g46(46);
    s += g47(47);
    s += g48(48);
    s += g49(49);
    s += g50(50);
    s += g51(51);
    s += g52(52);
    s += g53(53);
    s += g54(54);
    s += g55(55);
    s += g56(56);
    s += g57(57);
    s += g58(58);
    s += g59(59);
    s += g60(60);
    s += g61(61);
    s += g62(62);
    s += g63(63);
    printf("%sbigcode=%d\n", tag, s);
    return s % 256;
}
