# portrange 0-6000

I captured this trace using:

```shell
PF_VERBOSE=1 ../deps/luajit/usr/local/bin/luajit -jv -jdump=T \
  pflua-match ~/src/pflua-bench/savefiles/wingolog.org.pcap \
  "portrange 0-6000" \
  > ~/src/pflua-bench/results/wingolog.org-2/trace.md
```

## Compiled Lua filter

```lua
return function(P,length)
   if not (length >= 34) then return false end
   do
      local v1 = ffi.cast("uint16_t*", P+12)[0]
      if not (v1 == 8) then goto L3 end
      do
         local v2 = P[23]
         if v2 == 6 then goto L4 end
         do
            if v2 == 17 then goto L4 end
            do
               if not (v2 == 132) then return false end
            end
         end
::L4::
         do
            local v3 = ffi.cast("uint16_t*", P+20)[0]
            local v4 = bit.band(v3,65311)
            if not (v4 == 0) then return false end
            do
               local v5 = P[14]
               local v6 = bit.band(v5,15)
               local v7 = bit.lshift(v6,2)
               local v8 = v7+16
               if not (v8 <= length) then return false end
               do
                  local v9 = v7+14
                  local v10 = ffi.cast("uint16_t*", P+v9)[0]
                  local v11 = bit.rshift(bit.bswap(v10), 16)
                  if v11 <= 6000 then return true end
                  do
                     local v12 = v7+18
                     if not (v12 <= length) then return false end
                     do
                        local v13 = ffi.cast("uint16_t*", P+v8)[0]
                        local v14 = bit.rshift(bit.bswap(v13), 16)
                        do return v14 <= 6000 end
                     end
                  end
               end
            end
         end
      end
::L3::
      do
         if not (length >= 56) then return false end
         do
            if not (v1 == 56710) then return false end
            do
               local v15 = P[20]
               if v15 == 6 then goto L13 end
               do
                  if not (v15 == 44) then goto L14 end
                  do
                     local v16 = P[54]
                     if v16 == 6 then goto L13 end
                  end
               end
::L14::
               do
                  if v15 == 17 then goto L13 end
                  do
                     if not (v15 == 44) then goto L17 end
                     do
                        local v17 = P[54]
                        if v17 == 17 then goto L13 end
                     end
                  end
::L17::
                  do
                     if v15 == 132 then goto L13 end
                     do
                        if not (v15 == 44) then return false end
                        do
                           local v18 = P[54]
                           if not (v18 == 132) then return false end
                        end
                     end
                  end
               end
::L13::
               do
                  local v19 = ffi.cast("uint16_t*", P+54)[0]
                  local v20 = bit.rshift(bit.bswap(v19), 16)
                  if v20 <= 6000 then return true end
                  do
                     if not (length >= 58) then return false end
                     do
                        local v21 = ffi.cast("uint16_t*", P+56)[0]
                        local v22 = bit.rshift(bit.bswap(v21), 16)
                        do return v22 <= 6000 end
                     end
                  end
               end
            end
         end
      end
   end
end
```

## Traces

I'm skipping traces that get compiled before we enter the filter loop.

### 66: Inner loop

```
---- TRACE 66 start pflua-match:12
0006  UGET     5   0      ; ffi
0007  TGETS    5   5   0  ; "cast"
0008  KSTR     6   1      ; "struct pcap_record *"
0009  MOV      7   0
0010  CALL     5   2   3
0000  . FUNCC               ; ffi.cast
0011  UGET     6   0      ; ffi
0012  TGETS    6   6   0  ; "cast"
0013  KSTR     7   2      ; "unsigned char *"
0014  ADDVN    8   5   0  ; 1
0000  . . FUNCC               ; ffi.meta.__add
0015  CALL     6   2   3
0000  . FUNCC               ; ffi.cast
0016  TGETS    7   5   3  ; "incl_len"
0000  . . FUNCC               ; ffi.meta.__index
0017  ADDVV    7   6   7
0000  . . FUNCC               ; ffi.meta.__add
0018  MOV      8   2
0019  MOV      9   6
0020  TGETS   10   5   3  ; "incl_len"
0000  . . FUNCC               ; ffi.meta.__index
0021  CALL     8   2   3
0000  . FUNCF   18          ; "portrange 0-6000":1
0001  . KSHORT   2  34
0002  . ISLE     2   1
0003  . JMP      2 => 0006
0006  . GGET     2   0      ; "ffi"
0007  . TGETS    2   2   1  ; "cast"
0008  . KSTR     3   2      ; "uint16_t*"
0009  . ADDVN    4   0   0  ; 12
0000  . . . FUNCC               ; ffi.meta.__add
0010  . CALL     2   2   3
0000  . . FUNCC               ; ffi.cast
0011  . TGETB    2   2   0
0000  . . . FUNCC               ; ffi.meta.__index
0012  . ISEQN    2   1      ; 8
0013  . JMP      3 => 0015
0015  . TGETB    3   0  23
0000  . . . FUNCC               ; ffi.meta.__index
0016  . ISNEN    3   2      ; 6
0017  . JMP      4 => 0019
0018  . JMP      4 => 0026
0026  . GGET     4   0      ; "ffi"
0027  . TGETS    4   4   1  ; "cast"
0028  . KSTR     5   2      ; "uint16_t*"
0029  . ADDVN    6   0   5  ; 20
0000  . . . FUNCC               ; ffi.meta.__add
0030  . CALL     4   2   3
0000  . . FUNCC               ; ffi.cast
0031  . TGETB    4   4   0
0000  . . . FUNCC               ; ffi.meta.__index
0032  . GGET     5   3      ; "bit"
0033  . TGETS    5   5   4  ; "band"
0034  . MOV      6   4
0035  . KNUM     7   6      ; 65311
0036  . CALL     5   2   3
0000  . . FUNCC               ; bit.band
0037  . ISEQN    5   7      ; 0
0038  . JMP      6 => 0041
0041  . TGETB    6   0  14
0000  . . . FUNCC               ; ffi.meta.__index
0042  . GGET     7   3      ; "bit"
0043  . TGETS    7   7   4  ; "band"
0044  . MOV      8   6
0045  . KSHORT   9  15
0046  . CALL     7   2   3
0000  . . FUNCC               ; bit.band
0047  . GGET     8   3      ; "bit"
0048  . TGETS    8   8   5  ; "lshift"
0049  . MOV      9   7
0050  . KSHORT  10   2
0051  . CALL     8   2   3
0000  . . FUNCC               ; bit.lshift
0052  . ADDVN    9   8   8  ; 16
0053  . ISLE     9   1
0054  . JMP     10 => 0057
0057  . ADDVN   10   8   9  ; 14
0058  . GGET    11   0      ; "ffi"
0059  . TGETS   11  11   1  ; "cast"
0060  . KSTR    12   2      ; "uint16_t*"
0061  . ADDVV   13   0  10
0000  . . . FUNCC               ; ffi.meta.__add
0062  . CALL    11   2   3
0000  . . FUNCC               ; ffi.cast
0063  . TGETB   11  11   0
0000  . . . FUNCC               ; ffi.meta.__index
0064  . GGET    12   3      ; "bit"
0065  . TGETS   12  12   6  ; "rshift"
0066  . GGET    13   3      ; "bit"
0067  . TGETS   13  13   7  ; "bswap"
0068  . MOV     14  11
0069  . CALL    13   2   2
0000  . . FUNCC               ; bit.bswap
0070  . KSHORT  14  16
0071  . CALL    12   2   3
0000  . . FUNCC               ; bit.rshift
0072  . KSHORT  13 6000
0073  . ISGT    12  13
0074  . JMP     13 => 0077
0075  . KPRI    13   2
0076  . RET1    13   2
0022  ISF          8
0023  JMP      9 => 0025
0024  ADDVN    4   4   0  ; 1
0025  ADDVN    3   3   0  ; 1
0026  MOV      0   7
0027  JMP      5 => 0003
0003  ISGE     0   1
0004  JMP      5 => 0028
0000  . . FUNCC               ; ffi.meta.__lt
0005  LOOP     5 => 0028
---- TRACE 66 IR
0001    fun SLOAD  #0    R
0002 >  p32 UREFO  0001  #0  
0003 >  tab ULOAD  0002
0004    int FLOAD  0003  tab.hmask
0005 >  int EQ     0004  +31 
0006    p32 FLOAD  0003  tab.node
0007 >  p32 HREFK  0006  "cast" @6
0008 >  fun HLOAD  0007
0009 >  cdt SLOAD  #1    T
0010 >  fun EQ     0008  ffi.cast
0011    u16 FLOAD  0009  cdata.ctypeid
0012 >  int EQ     0011  +181
0013    p64 FLOAD  0009  cdata.ptr
0014 }  cdt CNEWI  +183  0013
0015    p64 ADD    0013  +16 
0017 }  cdt CNEWI  +181  0015
0018    p64 ADD    0013  +8  
0019    u32 XLOAD  0018  
0020    num CONV   0019  num.u32
0021  + p64 ADD    0019  0015
0022 }+ cdt CNEWI  +181  0021
0023 >  fun SLOAD  #3    T
0024 >  fun EQ     0023  "portrange 0-6000":1
0025 >  num GE     0020  +34 
0026    tab FLOAD  "portrange 0-6000":1  func.env
0027    int FLOAD  0026  tab.hmask
0028 >  int EQ     0027  +63 
0029    p32 FLOAD  0026  tab.node
0030 >  p32 HREFK  0029  "ffi" @33
0031 >  tab HLOAD  0030
0032    int FLOAD  0031  tab.hmask
0033 >  int EQ     0032  +31 
0034    p32 FLOAD  0031  tab.node
0035 >  p32 HREFK  0034  "cast" @6
0036 >  fun HLOAD  0035
0037    p64 ADD    0013  +28 
0039 >  fun EQ     0036  ffi.cast
0041    u16 XLOAD  0037  
0042 >  int EQ     0041  +8  
0044    p64 ADD    0013  +39 
0045    u8  XLOAD  0044  
0046 >  int EQ     0045  +6  
0047    p64 ADD    0013  +36 
0050    u16 XLOAD  0047  
0051 >  p32 HREFK  0029  "bit" @38
0052 >  tab HLOAD  0051
0053    int FLOAD  0052  tab.hmask
0054 >  int EQ     0053  +15 
0055    p32 FLOAD  0052  tab.node
0056 >  p32 HREFK  0055  "band" @15
0057 >  fun HLOAD  0056
0058 >  fun EQ     0057  bit.band
0059    int BAND   0050  +65311
0060 >  int EQ     0059  +0  
0062    p64 ADD    0013  +30 
0063    u8  XLOAD  0062  
0064    int BAND   0063  +15 
0065 >  p32 HREFK  0055  "lshift" @13
0066 >  fun HLOAD  0065
0067 >  fun EQ     0066  bit.lshift
0068    int BSHL   0063  +2  
0069    int BAND   0068  +60 
0070 >  int ADDOV  0069  +16 
0071    num CONV   0070  num.int
0072 >  num LE     0071  0020
0073 >  int ADDOV  0069  +14 
0074    i64 CONV   0073  i64.int sext
0075    p64 ADD    0074  0015
0078    u16 XLOAD  0075  
0079 >  p32 HREFK  0055  "rshift" @5
0080 >  fun HLOAD  0079
0081 >  p32 HREFK  0055  "bswap" @7
0082 >  fun HLOAD  0081
0083 >  fun EQ     0082  bit.bswap
0084    int BSWAP  0078
0085 >  fun EQ     0080  bit.rshift
0086    int BSHR   0084  +16 
0087 >  int LE     0086  +6000
0088 >  num SLOAD  #5    T
0089  + num ADD    0088  +1  
0090 >  num SLOAD  #4    T
0091  + num ADD    0090  +1  
0092 >  cdt SLOAD  #2    T
0093    u16 FLOAD  0092  cdata.ctypeid
0094 >  int EQ     0093  +181
0095    p64 FLOAD  0092  cdata.ptr
0096 >  p64 UGT    0095  0021
0097 ------ LOOP ------------
0098 >  p32 UREFO  0001  #0  
0099 }  cdt CNEWI  +183  0021
0100    p64 ADD    0021  +16 
0101 }  cdt CNEWI  +181  0100
0102    p64 ADD    0021  +8  
0103    u32 XLOAD  0102  
0104    num CONV   0103  num.u32
0105  + p64 ADD    0103  0100
0106 }+ cdt CNEWI  +181  0105
0107 >  num GE     0104  +34 
0108    p64 ADD    0021  +28 
0109    u16 XLOAD  0108  
0110 >  int EQ     0109  +8  
0111    p64 ADD    0021  +39 
0112    u8  XLOAD  0111  
0113 >  int EQ     0112  +6  
0114    p64 ADD    0021  +36 
0115    u16 XLOAD  0114  
0116    int BAND   0115  +65311
0117 >  int EQ     0116  +0  
0118    p64 ADD    0021  +30 
0119    u8  XLOAD  0118  
0120    int BAND   0119  +15 
0121    int BSHL   0119  +2  
0122    int BAND   0121  +60 
0123 >  int ADDOV  0122  +16 
0124    num CONV   0123  num.int
0125 >  num LE     0124  0104
0126 >  int ADDOV  0122  +14 
0127    i64 CONV   0126  i64.int sext
0128    p64 ADD    0127  0100
0129    u16 XLOAD  0128  
0130    int BSWAP  0129
0131    int BSHR   0130  +16 
0132 >  int LE     0131  +6000
0133  + num ADD    0089  +1  
0134  + num ADD    0091  +1  
0135 >  p64 ULT    0105  0095
0136 }  cdt PHI    0022  0106
0137    p64 PHI    0021  0105
0138    num PHI    0089  0133
0139    num PHI    0091  0134
---- TRACE 66 mcode 1024
0bca9def  mov dword [0x40b934a0], 0x42
0bca9dfa  mov eax, edx
0bca9dfc  movsd xmm1, [0x419a23d0]
0bca9e05  movsd xmm0, [0x419a2370]
0bca9e0e  mov ecx, [rax-0x8]
0bca9e11  mov edi, [rcx+0x14]
0bca9e14  mov ecx, [rdi+0x10]
0bca9e17  cmp dword [rcx+0x4], -0x0c
0bca9e1b  jnz 0x0bca0010	->0
0bca9e21  mov ecx, [rcx]
0bca9e23  cmp dword [rcx+0x1c], +0x1f
0bca9e27  jnz 0x0bca0010	->0
0bca9e2d  mov edx, [rcx+0x14]
0bca9e30  mov rdi, 0xfffffffb40bb1838
0bca9e3a  cmp rdi, [rdx+0x98]
0bca9e41  jnz 0x0bca0010	->0
0bca9e47  cmp dword [rdx+0x94], -0x09
0bca9e4e  jnz 0x0bca0010	->0
0bca9e54  cmp dword [rax+0x4], -0x0b
0bca9e58  jnz 0x0bca0010	->0
0bca9e5e  mov ecx, [rax]
0bca9e60  cmp dword [rdx+0x90], 0x40027090
0bca9e6a  jnz 0x0bca0010	->0
0bca9e70  movzx edx, word [rcx+0x6]
0bca9e74  cmp edx, 0xb5
0bca9e7a  jnz 0x0bca0010	->0
0bca9e80  mov r9, [rcx+0x8]
0bca9e84  mov [rsp+0x8], r9
0bca9e89  mov rdx, r9
0bca9e8c  add rdx, +0x10
0bca9e90  mov ebp, [r9+0x8]
0bca9e94  xorps xmm2, xmm2
0bca9e97  cvtsi2sd xmm2, rbp
0bca9e9c  add rbp, rdx
0bca9e9f  cmp dword [rax+0x14], -0x09
0bca9ea3  jnz 0x0bca0010	->0
0bca9ea9  cmp dword [rax+0x10], 0x4199b700
0bca9eb0  jnz 0x0bca0010	->0
0bca9eb6  ucomisd xmm2, xmm1
0bca9eba  jb 0x0bca0014	->1
0bca9ec0  mov ecx, [0x4199b708]
0bca9ec7  cmp dword [rcx+0x1c], +0x3f
0bca9ecb  jnz 0x0bca0018	->2
0bca9ed1  mov ecx, [rcx+0x14]
0bca9ed4  mov rdi, 0xfffffffb40b9ac60
0bca9ede  cmp rdi, [rcx+0x320]
0bca9ee5  jnz 0x0bca0018	->2
0bca9eeb  cmp dword [rcx+0x31c], -0x0c
0bca9ef2  jnz 0x0bca0018	->2
0bca9ef8  mov ebx, [rcx+0x318]
0bca9efe  cmp dword [rbx+0x1c], +0x1f
0bca9f02  jnz 0x0bca0018	->2
0bca9f08  mov ebx, [rbx+0x14]
0bca9f0b  mov rdi, 0xfffffffb40bb1838
0bca9f15  cmp rdi, [rbx+0x98]
0bca9f1c  jnz 0x0bca0018	->2
0bca9f22  cmp dword [rbx+0x94], -0x09
0bca9f29  jnz 0x0bca0018	->2
0bca9f2f  cmp dword [rbx+0x90], 0x40027090
0bca9f39  jnz 0x0bca0018	->2
0bca9f3f  movzx ebx, word [r9+0x1c]
0bca9f44  cmp ebx, +0x08
0bca9f47  jnz 0x0bca001c	->3
0bca9f4d  movzx esi, byte [r9+0x27]
0bca9f52  cmp esi, +0x06
0bca9f55  jnz 0x0bca0020	->4
0bca9f5b  movzx edi, word [r9+0x24]
0bca9f60  mov r15, 0xfffffffb40b99cf0
0bca9f6a  cmp r15, [rcx+0x398]
0bca9f71  jnz 0x0bca0024	->5
0bca9f77  cmp dword [rcx+0x394], -0x0c
0bca9f7e  jnz 0x0bca0024	->5
0bca9f84  mov ecx, [rcx+0x390]
0bca9f8a  cmp dword [rcx+0x1c], +0x0f
0bca9f8e  jnz 0x0bca0024	->5
0bca9f94  mov ecx, [rcx+0x14]
0bca9f97  mov r15, 0xfffffffb40b9a128
0bca9fa1  cmp r15, [rcx+0x170]
0bca9fa8  jnz 0x0bca0024	->5
0bca9fae  cmp dword [rcx+0x16c], -0x09
0bca9fb5  jnz 0x0bca0024	->5
0bca9fbb  cmp dword [rcx+0x168], 0x40b9a100
0bca9fc5  jnz 0x0bca0024	->5
0bca9fcb  mov r8d, edi
0bca9fce  and r8d, 0xff1f
0bca9fd5  jnz 0x0bca0028	->6
0bca9fdb  movzx r9d, byte [r9+0x1e]
0bca9fe0  mov r10d, r9d
0bca9fe3  and r10d, +0x0f
0bca9fe7  mov r15, 0xfffffffb40b99fc0
0bca9ff1  cmp r15, [rcx+0x140]
0bca9ff8  jnz 0x0bca002c	->7
0bca9ffe  cmp dword [rcx+0x13c], -0x09
0bcaa005  jnz 0x0bca002c	->7
0bcaa00b  cmp dword [rcx+0x138], 0x40b99f98
0bcaa015  jnz 0x0bca002c	->7
0bcaa01b  mov r11d, r9d
0bcaa01e  shl r11d, 0x02
0bcaa022  and r11d, +0x3c
0bcaa026  mov r12d, r11d
0bcaa029  add r12d, +0x10
0bcaa02d  jo 0x0bca002c	->7
0bcaa033  xorps xmm3, xmm3
0bcaa036  cvtsi2sd xmm3, r12d
0bcaa03b  ucomisd xmm2, xmm3
0bcaa03f  jb 0x0bca0030	->8
0bcaa045  mov r13d, r11d
0bcaa048  add r13d, +0x0e
0bcaa04c  jo 0x0bca0034	->9
0bcaa052  movsxd r14, r13d
0bcaa055  movzx r14d, word [r14+rdx]
0bcaa05a  mov r15, 0xfffffffb40b9a008
0bcaa064  cmp r15, [rcx+0x80]
0bcaa06b  jnz 0x0bca0034	->9
0bcaa071  cmp dword [rcx+0x7c], -0x09
0bcaa075  jnz 0x0bca0034	->9
0bcaa07b  mov r15, 0xfffffffb40b99f78
0bcaa085  cmp r15, [rcx+0xb0]
0bcaa08c  jnz 0x0bca0034	->9
0bcaa092  cmp dword [rcx+0xac], -0x09
0bcaa099  jnz 0x0bca0034	->9
0bcaa09f  cmp dword [rcx+0xa8], 0x40b99f50
0bcaa0a9  jnz 0x0bca0034	->9
0bcaa0af  mov r15d, r14d
0bcaa0b2  bswap r15d
0bcaa0b5  cmp dword [rcx+0x78], 0x40b99fe0
0bcaa0bc  jnz 0x0bca0034	->9
0bcaa0c2  shr r15d, 0x10
0bcaa0c6  cmp r15d, 0x1770
0bcaa0cd  jg 0x0bca0038	->10
0bcaa0d3  cmp dword [rax+0x24], 0xfffeffff
0bcaa0da  jnb 0x0bca003c	->11
0bcaa0e0  movsd xmm6, [rax+0x20]
0bcaa0e5  addsd xmm6, xmm0
0bcaa0e9  cmp dword [rax+0x1c], 0xfffeffff
0bcaa0f0  jnb 0x0bca003c	->11
0bcaa0f6  movsd xmm7, [rax+0x18]
0bcaa0fb  addsd xmm7, xmm0
0bcaa0ff  cmp dword [rax+0xc], -0x0b
0bcaa103  jnz 0x0bca003c	->11
0bcaa109  mov eax, [rax+0x8]
0bcaa10c  movzx ecx, word [rax+0x6]
0bcaa110  cmp ecx, 0xb5
0bcaa116  jnz 0x0bca0040	->12
0bcaa11c  mov rax, [rax+0x8]
0bcaa120  cmp rbp, rax
0bcaa123  jnb 0x0bca0040	->12
->LOOP:
0bcaa129  mov rbx, rbp
0bcaa12c  mov r15, rbx
0bcaa12f  add r15, +0x10
0bcaa133  mov ebp, [rbx+0x8]
0bcaa136  xorps xmm5, xmm5
0bcaa139  cvtsi2sd xmm5, rbp
0bcaa13e  add rbp, r15
0bcaa141  ucomisd xmm5, xmm1
0bcaa145  jb 0x0bca0048	->14
0bcaa14b  movzx r14d, word [rbx+0x1c]
0bcaa150  cmp r14d, +0x08
0bcaa154  jnz 0x0bca004c	->15
0bcaa15a  movzx r13d, byte [rbx+0x27]
0bcaa15f  cmp r13d, +0x06
0bcaa163  jnz 0x0bca0050	->16
0bcaa169  movzx r12d, word [rbx+0x24]
0bcaa16e  mov edi, r12d
0bcaa171  and edi, 0xff1f
0bcaa177  jnz 0x0bca0054	->17
0bcaa17d  movzx esi, byte [rbx+0x1e]
0bcaa181  mov edx, esi
0bcaa183  and edx, +0x0f
0bcaa186  mov ecx, esi
0bcaa188  shl ecx, 0x02
0bcaa18b  and ecx, +0x3c
0bcaa18e  mov r11d, ecx
0bcaa191  add r11d, +0x10
0bcaa195  jo 0x0bca0058	->18
0bcaa19b  xorps xmm4, xmm4
0bcaa19e  cvtsi2sd xmm4, r11d
0bcaa1a3  ucomisd xmm5, xmm4
0bcaa1a7  jb 0x0bca005c	->19
0bcaa1ad  mov r10d, ecx
0bcaa1b0  add r10d, +0x0e
0bcaa1b4  jo 0x0bca0060	->20
0bcaa1ba  movsxd r9, r10d
0bcaa1bd  movzx r9d, word [r9+r15]
0bcaa1c2  mov r8d, r9d
0bcaa1c5  bswap r8d
0bcaa1c8  shr r8d, 0x10
0bcaa1cc  cmp r8d, 0x1770
0bcaa1d3  jg 0x0bca0064	->21
0bcaa1d9  addsd xmm6, xmm0
0bcaa1dd  addsd xmm7, xmm0
0bcaa1e1  cmp rbp, rax
0bcaa1e4  jb 0x0bcaa129	->LOOP
0bcaa1ea  jmp 0x0bca0068	->22
---- TRACE 66 stop -> loop
```

Note that the trace stops when the first port test succeeds.  The loop
is not tight but it's not bad either -- all the badness was hoisted
before the loop.

### 67: Second port test

Going from one trace to another seems to be terrible!

```
---- TRACE 67 start 66/21 "portrange 0-6000":32
0077  . ADDVN   13   8  10  ; 18
0078  . ISLE    13   1
0079  . JMP     14 => 0082
0082  . GGET    14   0      ; "ffi"
0083  . TGETS   14  14   1  ; "cast"
0084  . KSTR    15   2      ; "uint16_t*"
0085  . ADDVV   16   0   9
0000  . . . FUNCC               ; ffi.meta.__add
0086  . CALL    14   2   3
0000  . . FUNCC               ; ffi.cast
0087  . TGETB   14  14   0
0000  . . . FUNCC               ; ffi.meta.__index
0088  . GGET    15   3      ; "bit"
0089  . TGETS   15  15   6  ; "rshift"
0090  . GGET    16   3      ; "bit"
0091  . TGETS   16  16   7  ; "bswap"
0092  . MOV     17  14
0093  . CALL    16   2   2
0000  . . FUNCC               ; bit.bswap
0094  . KSHORT  17  16
0095  . CALL    15   2   3
0000  . . FUNCC               ; bit.rshift
0096  . KSHORT  16 6000
0097  . ISLE    15  16
0098  . JMP     16 => 0101
0101  . KPRI    16   2
0102  . RET1    16   2
0022  ISF          8
0023  JMP      9 => 0025
0024  ADDVN    4   4   0  ; 1
0025  ADDVN    3   3   0  ; 1
0026  MOV      0   7
0027  JMP      5 => 0003
0003  ISGE     0   1
0004  JMP      5 => 0028
0000  . . FUNCC               ; ffi.meta.__lt
0005  JLOOP    5  66
---- TRACE 67 IR
0001    num SLOAD  #4    PI
0002    num SLOAD  #5    PI
0003    num SLOAD  #11   PI
0004    u16 SLOAD  #12   PI
0005    u8  SLOAD  #13   PI
0006    u16 SLOAD  #14   PI
0007    int SLOAD  #15   PI
0008    u8  SLOAD  #16   PI
0009    int SLOAD  #17   PI
0010    int SLOAD  #18   PI
0011    int SLOAD  #19   PI
0012    int SLOAD  #20   PI
0013    u16 SLOAD  #21   PI
0014    int SLOAD  #22   PI
0015    p64 PVAL   #21 
0016    p64 PVAL   #100
0017    p64 PVAL   #105
0018  + cdt CNEWI  +181  0015
0019 }  cdt CNEWI  +183  0015
0020 }  cdt CNEWI  +181  0016
0021  + cdt CNEWI  +181  0017
0022 >  nil GCSTEP 
0023 >  int ADDOV  0010  +18 
0024    num CONV   0023  num.int
0025 >  num LE     0024  0003
0026    tab FLOAD  "portrange 0-6000":1  func.env
0027    int FLOAD  0026  tab.hmask
0028 >  int EQ     0027  +63 
0029    p32 FLOAD  0026  tab.node
0030 >  p32 HREFK  0029  "ffi" @33
0031 >  tab HLOAD  0030
0032    int FLOAD  0031  tab.hmask
0033 >  int EQ     0032  +31 
0034    p32 FLOAD  0031  tab.node
0035 >  p32 HREFK  0034  "cast" @6
0036 >  fun HLOAD  0035
0037    i64 CONV   0011  i64.int sext
0038    p64 ADD    0037  0016
0039 }  cdt CNEWI  +181  0038
0040 >  fun EQ     0036  ffi.cast
0041 }  cdt CNEWI  +184  0038
0042    u16 XLOAD  0038  
0043 >  p32 HREFK  0029  "bit" @38
0044 >  tab HLOAD  0043
0045    int FLOAD  0044  tab.hmask
0046 >  int EQ     0045  +15 
0047    p32 FLOAD  0044  tab.node
0048 >  p32 HREFK  0047  "rshift" @5
0049 >  fun HLOAD  0048
0050 >  p32 HREFK  0047  "bswap" @7
0051 >  fun HLOAD  0050
0052 >  fun EQ     0051  bit.bswap
0053    int BSWAP  0042
0054 >  fun EQ     0049  bit.rshift
0055    int BSHR   0053  +16 
0056 >  int LE     0055  +6000
0057    num ADD    0002  +1  
0058    num ADD    0001  +1  
0059 >  cdt SLOAD  #2    T
0060    u16 FLOAD  0059  cdata.ctypeid
0061 >  int EQ     0060  +181
0062    p64 FLOAD  0059  cdata.ptr
0063 >  p64 UGT    0062  0017
---- TRACE 67 mcode 729
0bca9b13  mov eax, r13d
0bca9b16  mov r13, r15
0bca9b19  mov r15d, r14d
0bca9b1c  mov r14, rbx
0bca9b1f  mov ebx, eax
0bca9b21  add rsp, -0x50
0bca9b25  mov dword [0x40b934a0], 0x43
0bca9b30  movsd [rsp+0x30], xmm7
0bca9b36  movsd [rsp+0x28], xmm6
0bca9b3c  movsd [rsp+0x38], xmm5
0bca9b42  mov [rsp+0x18], r15d
0bca9b47  mov [rsp+0x1c], ebx
0bca9b4b  mov [rsp+0x20], r12d
0bca9b50  mov [rsp+0x48], edi
0bca9b54  mov [rsp+0x40], esi
0bca9b58  mov [rsp+0x44], edx
0bca9b5c  mov [rsp+0x58], ecx
0bca9b60  mov [rsp+0x54], r11d
0bca9b65  mov [rsp+0x50], r10d
0bca9b6a  mov [rsp+0x4c], r9d
0bca9b6f  mov [rsp+0x8], r8d
0bca9b74  mov edi, [0x40b934ac]
0bca9b7b  mov esi, 0x10
0bca9b80  call 0x0041f4e0	->lj_mem_newgco
0bca9b85  movzx ecx, byte [0x40b933e0]
0bca9b8d  and ecx, +0x03
0bca9b90  or ecx, 0x00b50a00
0bca9b96  mov [rax+0x4], ecx
0bca9b99  mov [rax+0x8], r14
0bca9b9d  mov r15d, eax
0bca9ba0  mov edi, [0x40b934ac]
0bca9ba7  mov esi, 0x10
0bca9bac  call 0x0041f4e0	->lj_mem_newgco
0bca9bb1  movzx ecx, byte [0x40b933e0]
0bca9bb9  and ecx, +0x03
0bca9bbc  or ecx, 0x00b50a00
0bca9bc2  mov [rax+0x4], ecx
0bca9bc5  mov [rax+0x8], rbp
0bca9bc9  mov [rsp+0x24], eax
0bca9bcd  mov edi, [0x40b933d8]
0bca9bd4  cmp edi, [0x40b933dc]
0bca9bdb  jb 0x0bca9bf4
0bca9bdd  mov esi, 0x2
0bca9be2  mov edi, 0x40b933b8
0bca9be7  call 0x0041f3d0	->lj_gc_step_jit
0bca9bec  test eax, eax
0bca9bee  jnz 0x0bca0010	->0
0bca9bf4  mov r11d, [rsp+0x58]
0bca9bf9  mov r10d, [rsp+0x54]
0bca9bfe  mov eax, [rsp+0x24]
0bca9c02  movsd xmm7, [rsp+0x38]
0bca9c08  movsd xmm5, [rsp+0x30]
0bca9c0e  movsd xmm4, [rsp+0x28]
0bca9c14  movsd xmm3, [0x419a2370]
0bca9c1d  mov ebx, r11d
0bca9c20  add ebx, +0x12
0bca9c23  jo 0x0bca0010	->0
0bca9c29  mov [rsp+0xc], ebx
0bca9c2d  xorps xmm6, xmm6
0bca9c30  cvtsi2sd xmm6, ebx
0bca9c34  ucomisd xmm7, xmm6
0bca9c38  jb 0x0bca0014	->1
0bca9c3e  mov ebx, [0x4199b708]
0bca9c45  cmp dword [rbx+0x1c], +0x3f
0bca9c49  jnz 0x0bca0018	->2
0bca9c4f  mov r12d, [rbx+0x14]
0bca9c53  mov rdi, 0xfffffffb40b9ac60
0bca9c5d  cmp rdi, [r12+0x320]
0bca9c65  jnz 0x0bca0018	->2
0bca9c6b  cmp dword [r12+0x31c], -0x0c
0bca9c74  jnz 0x0bca0018	->2
0bca9c7a  mov ebx, [r12+0x318]
0bca9c82  cmp dword [rbx+0x1c], +0x1f
0bca9c86  jnz 0x0bca0018	->2
0bca9c8c  mov edi, [rbx+0x14]
0bca9c8f  mov rbx, 0xfffffffb40bb1838
0bca9c99  cmp rbx, [rdi+0x98]
0bca9ca0  jnz 0x0bca0018	->2
0bca9ca6  cmp dword [rdi+0x94], -0x09
0bca9cad  jnz 0x0bca0018	->2
0bca9cb3  movsxd rbx, r10d
0bca9cb6  cmp dword [rdi+0x90], 0x40027090
0bca9cc0  jnz 0x0bca0018	->2
0bca9cc6  movzx ebx, word [rbx+r13]
0bca9ccb  mov [rsp+0x10], ebx
0bca9ccf  mov rdi, 0xfffffffb40b99cf0
0bca9cd9  cmp rdi, [r12+0x398]
0bca9ce1  jnz 0x0bca0018	->2
0bca9ce7  cmp dword [r12+0x394], -0x0c
0bca9cf0  jnz 0x0bca0018	->2
0bca9cf6  mov r12d, [r12+0x390]
0bca9cfe  cmp dword [r12+0x1c], +0x0f
0bca9d04  jnz 0x0bca0018	->2
0bca9d0a  mov r12d, [r12+0x14]
0bca9d0f  mov rdi, 0xfffffffb40b9a008
0bca9d19  cmp rdi, [r12+0x80]
0bca9d21  jnz 0x0bca0018	->2
0bca9d27  cmp dword [r12+0x7c], -0x09
0bca9d2d  jnz 0x0bca0018	->2
0bca9d33  mov rdi, 0xfffffffb40b99f78
0bca9d3d  cmp rdi, [r12+0xb0]
0bca9d45  jnz 0x0bca0018	->2
0bca9d4b  cmp dword [r12+0xac], -0x09
0bca9d54  jnz 0x0bca0018	->2
0bca9d5a  cmp dword [r12+0xa8], 0x40b99f50
0bca9d66  jnz 0x0bca0018	->2
0bca9d6c  bswap ebx
0bca9d6e  cmp dword [r12+0x78], 0x40b99fe0
0bca9d77  jnz 0x0bca0018	->2
0bca9d7d  shr ebx, 0x10
0bca9d80  mov [rsp+0x14], ebx
0bca9d84  cmp dword [rsp+0x14], 0x1770
0bca9d8c  jg 0x0bca001c	->3
0bca9d92  mov edx, [0x40b934b0]
0bca9d99  movaps xmm6, xmm4
0bca9d9c  addsd xmm6, xmm3
0bca9da0  movaps xmm7, xmm5
0bca9da3  addsd xmm7, xmm3
0bca9da7  cmp dword [rdx+0xc], -0x0b
0bca9dab  jnz 0x0bca0020	->4
0bca9db1  mov ebx, [rdx+0x8]
0bca9db4  movzx r15d, word [rbx+0x6]
0bca9db9  cmp r15d, 0xb5
0bca9dc0  jnz 0x0bca0024	->5
0bca9dc6  cmp rbp, [rbx+0x8]
0bca9dca  jnb 0x0bca0024	->5
0bca9dd0  movsd [rdx+0x20], xmm6
0bca9dd5  movsd [rdx+0x18], xmm7
0bca9dda  mov dword [rdx+0x4], 0xfffffff5
0bca9de1  mov [rdx], eax
0bca9de3  add rsp, +0x50
0bca9de7  jmp 0x0bca9def
---- TRACE 67 stop -> 66
```

### 68: Refinement of 67?

Since this one starts on line 32 of the filter, corresponding to the
declaration of `v12`, I can only think this is in some way a refinement
of trace 67.

```
---- TRACE 68 start 66/10 "portrange 0-6000":32
0077  . ADDVN   13   8  10  ; 18
0078  . ISLE    13   1
0079  . JMP     14 => 0082
0082  . GGET    14   0      ; "ffi"
0083  . TGETS   14  14   1  ; "cast"
0084  . KSTR    15   2      ; "uint16_t*"
0085  . ADDVV   16   0   9
0000  . . . FUNCC               ; ffi.meta.__add
0086  . CALL    14   2   3
0000  . . FUNCC               ; ffi.cast
0087  . TGETB   14  14   0
0000  . . . FUNCC               ; ffi.meta.__index
0088  . GGET    15   3      ; "bit"
0089  . TGETS   15  15   6  ; "rshift"
0090  . GGET    16   3      ; "bit"
0091  . TGETS   16  16   7  ; "bswap"
0092  . MOV     17  14
0093  . CALL    16   2   2
0000  . . FUNCC               ; bit.bswap
0094  . KSHORT  17  16
0095  . CALL    15   2   3
0000  . . FUNCC               ; bit.rshift
0096  . KSHORT  16 6000
0097  . ISLE    15  16
0098  . JMP     16 => 0101
0101  . KPRI    16   2
0102  . RET1    16   2
0022  ISF          8
0023  JMP      9 => 0025
0024  ADDVN    4   4   0  ; 1
0025  ADDVN    3   3   0  ; 1
0026  MOV      0   7
0027  JMP      5 => 0003
0003  ISGE     0   1
0004  JMP      5 => 0028
0000  . . FUNCC               ; ffi.meta.__lt
0005  JLOOP    5  66
---- TRACE 68 IR
0001    num SLOAD  #11   PI
0002    u16 SLOAD  #12   PI
0003    u8  SLOAD  #13   PI
0004    u16 SLOAD  #14   PI
0005    int SLOAD  #15   PI
0006    u8  SLOAD  #16   PI
0007    int SLOAD  #17   PI
0008    int SLOAD  #18   PI
0009    int SLOAD  #19   PI
0010    int SLOAD  #20   PI
0011    u16 SLOAD  #21   PI
0012    int SLOAD  #22   PI
0013    p64 PVAL   #13 
0014    p64 PVAL   #15 
0015    p64 PVAL   #21 
0016 }  cdt CNEWI  +183  0013
0017 }  cdt CNEWI  +181  0014
0018  + cdt CNEWI  +181  0015
0019 >  nil GCSTEP 
0020 >  int ADDOV  0008  +18 
0021    num CONV   0020  num.int
0022 >  num LE     0021  0001
0023    tab FLOAD  "portrange 0-6000":1  func.env
0024    int FLOAD  0023  tab.hmask
0025 >  int EQ     0024  +63 
0026    p32 FLOAD  0023  tab.node
0027 >  p32 HREFK  0026  "ffi" @33
0028 >  tab HLOAD  0027
0029    int FLOAD  0028  tab.hmask
0030 >  int EQ     0029  +31 
0031    p32 FLOAD  0028  tab.node
0032 >  p32 HREFK  0031  "cast" @6
0033 >  fun HLOAD  0032
0034    i64 CONV   0009  i64.int sext
0035    p64 ADD    0034  0014
0036 }  cdt CNEWI  +181  0035
0037 >  fun EQ     0033  ffi.cast
0038 }  cdt CNEWI  +184  0035
0039    u16 XLOAD  0035  
0040 >  p32 HREFK  0026  "bit" @38
0041 >  tab HLOAD  0040
0042    int FLOAD  0041  tab.hmask
0043 >  int EQ     0042  +15 
0044    p32 FLOAD  0041  tab.node
0045 >  p32 HREFK  0044  "rshift" @5
0046 >  fun HLOAD  0045
0047 >  p32 HREFK  0044  "bswap" @7
0048 >  fun HLOAD  0047
0049 >  fun EQ     0048  bit.bswap
0050    int BSWAP  0039
0051 >  fun EQ     0046  bit.rshift
0052    int BSHR   0050  +16 
0053 >  int LE     0052  +6000
0054 >  num SLOAD  #5    T
0055    num ADD    0054  +1  
0056 >  num SLOAD  #4    T
0057    num ADD    0056  +1  
0058 >  cdt SLOAD  #2    T
0059    u16 FLOAD  0058  cdata.ctypeid
0060 >  int EQ     0059  +181
0061    p64 FLOAD  0058  cdata.ptr
0062 >  p64 UGT    0061  0015
---- TRACE 68 mcode 659
0bca987d  mov ecx, ebx
0bca987f  mov ebx, r15d
0bca9882  mov r15, [rsp+0x8]
0bca9887  add rsp, -0x40
0bca988b  mov dword [0x40b934a0], 0x44
0bca9896  movsd [rsp+0x20], xmm2
0bca989c  mov [rsp+0x14], ecx
0bca98a0  mov [rsp+0x18], esi
0bca98a4  mov [rsp+0x1c], edi
0bca98a8  mov [rsp+0x38], r8d
0bca98ad  mov [rsp+0x3c], r9d
0bca98b2  mov [rsp+0x40], r10d
0bca98b7  mov [rsp+0x44], r11d
0bca98bc  mov [rsp+0x2c], ebx
0bca98c0  mov [rsp+0x30], rdx
0bca98c5  mov edi, [0x40b934ac]
0bca98cc  mov esi, 0x10
0bca98d1  call 0x0041f4e0	->lj_mem_newgco
0bca98d6  movzx ecx, byte [0x40b933e0]
0bca98de  and ecx, +0x03
0bca98e1  or ecx, 0x00b50a00
0bca98e7  mov [rax+0x4], ecx
0bca98ea  mov [rax+0x8], rbp
0bca98ee  mov [rsp+0x28], eax
0bca98f2  mov edi, [0x40b933d8]
0bca98f9  cmp edi, [0x40b933dc]
0bca9900  jb 0x0bca9919
0bca9902  mov esi, 0x1
0bca9907  mov edi, 0x40b933b8
0bca990c  call 0x0041f3d0	->lj_gc_step_jit
0bca9911  test eax, eax
0bca9913  jnz 0x0bca0010	->0
0bca9919  mov r11d, [rsp+0x44]
0bca991e  mov rdx, [rsp+0x30]
0bca9923  mov eax, [rsp+0x28]
0bca9927  movsd xmm5, [0x419a2370]
0bca9930  movsd xmm2, [rsp+0x20]
0bca9936  mov ebx, r11d
0bca9939  add ebx, +0x12
0bca993c  jo 0x0bca0010	->0
0bca9942  mov [rsp+0x8], ebx
0bca9946  xorps xmm7, xmm7
0bca9949  cvtsi2sd xmm7, ebx
0bca994d  ucomisd xmm2, xmm7
0bca9951  jb 0x0bca0014	->1
0bca9957  mov ebx, [0x4199b708]
0bca995e  cmp dword [rbx+0x1c], +0x3f
0bca9962  jnz 0x0bca0018	->2
0bca9968  mov edi, [rbx+0x14]
0bca996b  mov rsi, 0xfffffffb40b9ac60
0bca9975  cmp rsi, [rdi+0x320]
0bca997c  jnz 0x0bca0018	->2
0bca9982  cmp dword [rdi+0x31c], -0x0c
0bca9989  jnz 0x0bca0018	->2
0bca998f  mov ebx, [rdi+0x318]
0bca9995  cmp dword [rbx+0x1c], +0x1f
0bca9999  jnz 0x0bca0018	->2
0bca999f  mov esi, [rbx+0x14]
0bca99a2  mov rbx, 0xfffffffb40bb1838
0bca99ac  cmp rbx, [rsi+0x98]
0bca99b3  jnz 0x0bca0018	->2
0bca99b9  cmp dword [rsi+0x94], -0x09
0bca99c0  jnz 0x0bca0018	->2
0bca99c6  movsxd rbx, r12d
0bca99c9  cmp dword [rsi+0x90], 0x40027090
0bca99d3  jnz 0x0bca0018	->2
0bca99d9  movzx ebx, word [rbx+rdx]
0bca99dd  mov [rsp+0xc], ebx
0bca99e1  mov rsi, 0xfffffffb40b99cf0
0bca99eb  cmp rsi, [rdi+0x398]
0bca99f2  jnz 0x0bca0018	->2
0bca99f8  cmp dword [rdi+0x394], -0x0c
0bca99ff  jnz 0x0bca0018	->2
0bca9a05  mov edi, [rdi+0x390]
0bca9a0b  cmp dword [rdi+0x1c], +0x0f
0bca9a0f  jnz 0x0bca0018	->2
0bca9a15  mov esi, [rdi+0x14]
0bca9a18  mov rdi, 0xfffffffb40b9a008
0bca9a22  cmp rdi, [rsi+0x80]
0bca9a29  jnz 0x0bca0018	->2
0bca9a2f  cmp dword [rsi+0x7c], -0x09
0bca9a33  jnz 0x0bca0018	->2
0bca9a39  mov rdi, 0xfffffffb40b99f78
0bca9a43  cmp rdi, [rsi+0xb0]
0bca9a4a  jnz 0x0bca0018	->2
0bca9a50  cmp dword [rsi+0xac], -0x09
0bca9a57  jnz 0x0bca0018	->2
0bca9a5d  cmp dword [rsi+0xa8], 0x40b99f50
0bca9a67  jnz 0x0bca0018	->2
0bca9a6d  bswap ebx
0bca9a6f  cmp dword [rsi+0x78], 0x40b99fe0
0bca9a76  jnz 0x0bca0018	->2
0bca9a7c  shr ebx, 0x10
0bca9a7f  mov [rsp+0x10], ebx
0bca9a83  cmp dword [rsp+0x10], 0x1770
0bca9a8b  jg 0x0bca001c	->3
0bca9a91  mov ebx, [0x40b934b0]
0bca9a98  cmp dword [rbx+0x24], 0xfffeffff
0bca9a9f  jnb 0x0bca0020	->4
0bca9aa5  movsd xmm6, [rbx+0x20]
0bca9aaa  addsd xmm6, xmm5
0bca9aae  cmp dword [rbx+0x1c], 0xfffeffff
0bca9ab5  jnb 0x0bca0020	->4
0bca9abb  movsd xmm7, [rbx+0x18]
0bca9ac0  addsd xmm7, xmm5
0bca9ac4  cmp dword [rbx+0xc], -0x0b
0bca9ac8  jnz 0x0bca0020	->4
0bca9ace  mov ebx, [rbx+0x8]
0bca9ad1  mov edx, [0x40b934b0]
0bca9ad8  movzx r15d, word [rbx+0x6]
0bca9add  cmp r15d, 0xb5
0bca9ae4  jnz 0x0bca0024	->5
0bca9aea  cmp rbp, [rbx+0x8]
0bca9aee  jnb 0x0bca0024	->5
0bca9af4  movsd [rdx+0x20], xmm6
0bca9af9  movsd [rdx+0x18], xmm7
0bca9afe  mov dword [rdx+0x4], 0xfffffff5
0bca9b05  mov [rdx], eax
0bca9b07  add rsp, +0x40
0bca9b0b  jmp 0x0bca9def
---- TRACE 68 stop -> 66
```

### 69: UDP

Trace 66 is for TCP (protocol 6); this one is for UDP (protocol 17).
Otherwise it's the same as 66.

```
---- TRACE 69 start 66/4 "portrange 0-6000":10
0019  . ISNEN    3   3      ; 17
0020  . JMP      4 => 0022
0021  . JMP      4 => 0026
0026  . GGET     4   0      ; "ffi"
0027  . TGETS    4   4   1  ; "cast"
0028  . KSTR     5   2      ; "uint16_t*"
0029  . ADDVN    6   0   5  ; 20
0000  . . . FUNCC               ; ffi.meta.__add
0030  . CALL     4   2   3
0000  . . FUNCC               ; ffi.cast
0031  . TGETB    4   4   0
0000  . . . FUNCC               ; ffi.meta.__index
0032  . GGET     5   3      ; "bit"
0033  . TGETS    5   5   4  ; "band"
0034  . MOV      6   4
0035  . KNUM     7   6      ; 65311
0036  . CALL     5   2   3
0000  . . FUNCC               ; bit.band
0037  . ISEQN    5   7      ; 0
0038  . JMP      6 => 0041
0041  . TGETB    6   0  14
0000  . . . FUNCC               ; ffi.meta.__index
0042  . GGET     7   3      ; "bit"
0043  . TGETS    7   7   4  ; "band"
0044  . MOV      8   6
0045  . KSHORT   9  15
0046  . CALL     7   2   3
0000  . . FUNCC               ; bit.band
0047  . GGET     8   3      ; "bit"
0048  . TGETS    8   8   5  ; "lshift"
0049  . MOV      9   7
0050  . KSHORT  10   2
0051  . CALL     8   2   3
0000  . . FUNCC               ; bit.lshift
0052  . ADDVN    9   8   8  ; 16
0053  . ISLE     9   1
0054  . JMP     10 => 0057
0057  . ADDVN   10   8   9  ; 14
0058  . GGET    11   0      ; "ffi"
0059  . TGETS   11  11   1  ; "cast"
0060  . KSTR    12   2      ; "uint16_t*"
0061  . ADDVV   13   0  10
0000  . . . FUNCC               ; ffi.meta.__add
0062  . CALL    11   2   3
0000  . . FUNCC               ; ffi.cast
0063  . TGETB   11  11   0
0000  . . . FUNCC               ; ffi.meta.__index
0064  . GGET    12   3      ; "bit"
0065  . TGETS   12  12   6  ; "rshift"
0066  . GGET    13   3      ; "bit"
0067  . TGETS   13  13   7  ; "bswap"
0068  . MOV     14  11
0069  . CALL    13   2   2
0000  . . FUNCC               ; bit.bswap
0070  . KSHORT  14  16
0071  . CALL    12   2   3
0000  . . FUNCC               ; bit.rshift
0072  . KSHORT  13 6000
0073  . ISGT    12  13
0074  . JMP     13 => 0077
0075  . KPRI    13   2
0076  . RET1    13   2
0022  ISF          8
0023  JMP      9 => 0025
0024  ADDVN    4   4   0  ; 1
0025  ADDVN    3   3   0  ; 1
0026  MOV      0   7
0027  JMP      5 => 0003
0003  ISGE     0   1
0004  JMP      5 => 0028
0000  . . FUNCC               ; ffi.meta.__lt
0005  JLOOP    5  66
---- TRACE 69 IR
0001    num SLOAD  #11   PI
0002    u16 SLOAD  #12   PI
0003    u8  SLOAD  #13   PI
0004    p64 PVAL   #13 
0005    p64 PVAL   #15 
0006    p64 PVAL   #21 
0007 }  cdt CNEWI  +183  0004
0008 }  cdt CNEWI  +181  0005
0009  + cdt CNEWI  +181  0006
0010 >  nil GCSTEP 
0011 >  int EQ     0003  +17 
0012    tab FLOAD  "portrange 0-6000":1  func.env
0013    int FLOAD  0012  tab.hmask
0014 >  int EQ     0013  +63 
0015    p32 FLOAD  0012  tab.node
0016 >  p32 HREFK  0015  "ffi" @33
0017 >  tab HLOAD  0016
0018    int FLOAD  0017  tab.hmask
0019 >  int EQ     0018  +31 
0020    p32 FLOAD  0017  tab.node
0021 >  p32 HREFK  0020  "cast" @6
0022 >  fun HLOAD  0021
0023    p64 ADD    0005  +20 
0024 }  cdt CNEWI  +181  0023
0025 >  fun EQ     0022  ffi.cast
0026 }  cdt CNEWI  +184  0023
0027    u16 XLOAD  0023  
0028 >  p32 HREFK  0015  "bit" @38
0029 >  tab HLOAD  0028
0030    int FLOAD  0029  tab.hmask
0031 >  int EQ     0030  +15 
0032    p32 FLOAD  0029  tab.node
0033 >  p32 HREFK  0032  "band" @15
0034 >  fun HLOAD  0033
0035 >  fun EQ     0034  bit.band
0036    int BAND   0027  +65311
0037 >  int EQ     0036  +0  
0038    p64 ADD    0005  +14 
0039    u8  XLOAD  0038  
0040    int BAND   0039  +15 
0041 >  p32 HREFK  0032  "lshift" @13
0042 >  fun HLOAD  0041
0043 >  fun EQ     0042  bit.lshift
0044    int BSHL   0039  +2  
0045    int BAND   0044  +60 
0046 >  int ADDOV  0045  +16 
0047    num CONV   0046  num.int
0048 >  num LE     0047  0001
0049 >  int ADDOV  0045  +14 
0050    i64 CONV   0049  i64.int sext
0051    p64 ADD    0050  0005
0052 }  cdt CNEWI  +181  0051
0053 }  cdt CNEWI  +184  0051
0054    u16 XLOAD  0051  
0055 >  p32 HREFK  0032  "rshift" @5
0056 >  fun HLOAD  0055
0057 >  p32 HREFK  0032  "bswap" @7
0058 >  fun HLOAD  0057
0059 >  fun EQ     0058  bit.bswap
0060    int BSWAP  0054
0061 >  fun EQ     0056  bit.rshift
0062    int BSHR   0060  +16 
0063 >  int LE     0062  +6000
0064 >  num SLOAD  #5    T
0065    num ADD    0064  +1  
0066 >  num SLOAD  #4    T
0067    num ADD    0066  +1  
0068 >  cdt SLOAD  #2    T
0069    u16 FLOAD  0068  cdata.ctypeid
0070 >  int EQ     0069  +181
0071    p64 FLOAD  0068  cdata.ptr
0072 >  p64 UGT    0071  0006
---- TRACE 69 mcode 792
0bca9562  mov r15, [rsp+0x8]
0bca9567  add rsp, -0x20
0bca956b  mov dword [0x40b934a0], 0x45
0bca9576  movsd [rsp+0x10], xmm2
0bca957c  mov [rsp+0x8], ebx
0bca9580  mov [rsp+0x20], esi
0bca9584  mov [rsp+0x18], rdx
0bca9589  mov edi, [0x40b934ac]
0bca9590  mov esi, 0x10
0bca9595  call 0x0041f4e0	->lj_mem_newgco
0bca959a  movzx ecx, byte [0x40b933e0]
0bca95a2  and ecx, +0x03
0bca95a5  or ecx, 0x00b50a00
0bca95ab  mov [rax+0x4], ecx
0bca95ae  mov [rax+0x8], rbp
0bca95b2  mov [rsp+0xc], eax
0bca95b6  mov edi, [0x40b933d8]
0bca95bd  cmp edi, [0x40b933dc]
0bca95c4  jb 0x0bca95dd
0bca95c6  mov esi, 0x1
0bca95cb  mov edi, 0x40b933b8
0bca95d0  call 0x0041f3d0	->lj_gc_step_jit
0bca95d5  test eax, eax
0bca95d7  jnz 0x0bca0010	->0
0bca95dd  mov esi, [rsp+0x20]
0bca95e1  mov rdx, [rsp+0x18]
0bca95e6  mov eax, [rsp+0xc]
0bca95ea  movsd xmm5, [0x419a2370]
0bca95f3  movsd xmm2, [rsp+0x10]
0bca95f9  cmp esi, +0x11
0bca95fc  jnz 0x0bca0014	->1
0bca9602  mov ebx, [0x4199b708]
0bca9609  cmp dword [rbx+0x1c], +0x3f
0bca960d  jnz 0x0bca0018	->2
0bca9613  mov ebx, [rbx+0x14]
0bca9616  mov rdi, 0xfffffffb40b9ac60
0bca9620  cmp rdi, [rbx+0x320]
0bca9627  jnz 0x0bca0018	->2
0bca962d  cmp dword [rbx+0x31c], -0x0c
0bca9634  jnz 0x0bca0018	->2
0bca963a  mov r14d, [rbx+0x318]
0bca9641  cmp dword [r14+0x1c], +0x1f
0bca9646  jnz 0x0bca0018	->2
0bca964c  mov r14d, [r14+0x14]
0bca9650  mov rdi, 0xfffffffb40bb1838
0bca965a  cmp rdi, [r14+0x98]
0bca9661  jnz 0x0bca0018	->2
0bca9667  cmp dword [r14+0x94], -0x09
0bca966f  jnz 0x0bca0018	->2
0bca9675  cmp dword [r14+0x90], 0x40027090
0bca9680  jnz 0x0bca0018	->2
0bca9686  movzx r14d, word [rdx+0x14]
0bca968b  mov rdi, 0xfffffffb40b99cf0
0bca9695  cmp rdi, [rbx+0x398]
0bca969c  jnz 0x0bca0018	->2
0bca96a2  cmp dword [rbx+0x394], -0x0c
0bca96a9  jnz 0x0bca0018	->2
0bca96af  mov ebx, [rbx+0x390]
0bca96b5  cmp dword [rbx+0x1c], +0x0f
0bca96b9  jnz 0x0bca0018	->2
0bca96bf  mov ebx, [rbx+0x14]
0bca96c2  mov rdi, 0xfffffffb40b9a128
0bca96cc  cmp rdi, [rbx+0x170]
0bca96d3  jnz 0x0bca0018	->2
0bca96d9  cmp dword [rbx+0x16c], -0x09
0bca96e0  jnz 0x0bca0018	->2
0bca96e6  cmp dword [rbx+0x168], 0x40b9a100
0bca96f0  jnz 0x0bca0018	->2
0bca96f6  mov r13d, r14d
0bca96f9  and r13d, 0xff1f
0bca9700  jnz 0x0bca001c	->3
0bca9706  movzx r12d, byte [rdx+0xe]
0bca970b  mov edi, r12d
0bca970e  and edi, +0x0f
0bca9711  mov rcx, 0xfffffffb40b99fc0
0bca971b  cmp rcx, [rbx+0x140]
0bca9722  jnz 0x0bca0020	->4
0bca9728  cmp dword [rbx+0x13c], -0x09
0bca972f  jnz 0x0bca0020	->4
0bca9735  cmp dword [rbx+0x138], 0x40b99f98
0bca973f  jnz 0x0bca0020	->4
0bca9745  mov ecx, r12d
0bca9748  shl ecx, 0x02
0bca974b  and ecx, +0x3c
0bca974e  mov r11d, ecx
0bca9751  add r11d, +0x10
0bca9755  jo 0x0bca0020	->4
0bca975b  xorps xmm7, xmm7
0bca975e  cvtsi2sd xmm7, r11d
0bca9763  ucomisd xmm2, xmm7
0bca9767  jb 0x0bca0024	->5
0bca976d  mov r10d, ecx
0bca9770  add r10d, +0x0e
0bca9774  jo 0x0bca0028	->6
0bca977a  movsxd r9, r10d
0bca977d  movzx r9d, word [r9+rdx]
0bca9782  mov r8, 0xfffffffb40b9a008
0bca978c  cmp r8, [rbx+0x80]
0bca9793  jnz 0x0bca0028	->6
0bca9799  cmp dword [rbx+0x7c], -0x09
0bca979d  jnz 0x0bca0028	->6
0bca97a3  mov r8, 0xfffffffb40b99f78
0bca97ad  cmp r8, [rbx+0xb0]
0bca97b4  jnz 0x0bca0028	->6
0bca97ba  cmp dword [rbx+0xac], -0x09
0bca97c1  jnz 0x0bca0028	->6
0bca97c7  cmp dword [rbx+0xa8], 0x40b99f50
0bca97d1  jnz 0x0bca0028	->6
0bca97d7  mov r8d, r9d
0bca97da  bswap r8d
0bca97dd  cmp dword [rbx+0x78], 0x40b99fe0
0bca97e4  jnz 0x0bca0028	->6
0bca97ea  shr r8d, 0x10
0bca97ee  cmp r8d, 0x1770
0bca97f5  jg 0x0bca002c	->7
0bca97fb  mov ebx, [0x40b934b0]
0bca9802  cmp dword [rbx+0x24], 0xfffeffff
0bca9809  jnb 0x0bca0030	->8
0bca980f  movsd xmm6, [rbx+0x20]
0bca9814  addsd xmm6, xmm5
0bca9818  cmp dword [rbx+0x1c], 0xfffeffff
0bca981f  jnb 0x0bca0030	->8
0bca9825  movsd xmm7, [rbx+0x18]
0bca982a  addsd xmm7, xmm5
0bca982e  cmp dword [rbx+0xc], -0x0b
0bca9832  jnz 0x0bca0030	->8
0bca9838  mov ebx, [rbx+0x8]
0bca983b  mov edx, [0x40b934b0]
0bca9842  movzx r15d, word [rbx+0x6]
0bca9847  cmp r15d, 0xb5
0bca984e  jnz 0x0bca0034	->9
0bca9854  cmp rbp, [rbx+0x8]
0bca9858  jnb 0x0bca0034	->9
0bca985e  movsd [rdx+0x20], xmm6
0bca9863  movsd [rdx+0x18], xmm7
0bca9868  mov dword [rdx+0x4], 0xfffffff5
0bca986f  mov [rdx], eax
0bca9871  add rsp, +0x20
0bca9875  jmp 0x0bca9def
---- TRACE 69 stop -> 66
```

### 70: Short packets

If the packet is less than 34 bytes long, this trace is visited.

```
---- TRACE 70 start 66/1 "portrange 0-6000":2
0004  . KPRI     2   1
0005  . RET1     2   2
0022  ISF          8
0023  JMP      9 => 0025
0025  ADDVN    3   3   0  ; 1
0026  MOV      0   7
0027  JMP      5 => 0003
0003  ISGE     0   1
0004  JMP      5 => 0028
0000  . . FUNCC               ; ffi.meta.__lt
0005  JLOOP    5  66
---- TRACE 70 IR
0001    p64 PVAL   #13 
0002    p64 PVAL   #15 
0003    p64 PVAL   #21 
0004 }  cdt CNEWI  +183  0001
0005 }  cdt CNEWI  +181  0002
0006  + cdt CNEWI  +181  0003
0007 >  nil GCSTEP 
0008 >  num SLOAD  #4    T
0009    num ADD    0008  +1  
0010 >  cdt SLOAD  #2    T
0011    u16 FLOAD  0010  cdata.ctypeid
0012 >  int EQ     0011  +181
0013    p64 FLOAD  0010  cdata.ptr
0014 >  p64 UGT    0013  0003
---- TRACE 70 mcode 222
0bca9481  mov r15, [rsp+0x8]
0bca9486  add rsp, -0x10
0bca948a  mov dword [0x40b934a0], 0x46
0bca9495  mov [rsp+0x10], rdx
0bca949a  mov ebx, [0x40b934b0]
0bca94a1  mov edi, [0x40b934ac]
0bca94a8  mov esi, 0x10
0bca94ad  call 0x0041f4e0	->lj_mem_newgco
0bca94b2  movzx ecx, byte [0x40b933e0]
0bca94ba  and ecx, +0x03
0bca94bd  or ecx, 0x00b50a00
0bca94c3  mov [rax+0x4], ecx
0bca94c6  mov [rax+0x8], rbp
0bca94ca  mov [rsp+0x8], eax
0bca94ce  mov edi, [0x40b933d8]
0bca94d5  cmp edi, [0x40b933dc]
0bca94dc  jb 0x0bca94f5
0bca94de  mov esi, 0x1
0bca94e3  mov edi, 0x40b933b8
0bca94e8  call 0x0041f3d0	->lj_gc_step_jit
0bca94ed  test eax, eax
0bca94ef  jnz 0x0bca0010	->0
0bca94f5  mov eax, [rsp+0x8]
0bca94f9  movsd xmm6, [0x419a2370]
0bca9502  cmp dword [rbx+0x1c], 0xfffeffff
0bca9509  jnb 0x0bca0010	->0
0bca950f  movsd xmm7, [rbx+0x18]
0bca9514  addsd xmm7, xmm6
0bca9518  cmp dword [rbx+0xc], -0x0b
0bca951c  jnz 0x0bca0010	->0
0bca9522  mov ebx, [rbx+0x8]
0bca9525  mov edx, [0x40b934b0]
0bca952c  movzx r15d, word [rbx+0x6]
0bca9531  cmp r15d, 0xb5
0bca9538  jnz 0x0bca0014	->1
0bca953e  cmp rbp, [rbx+0x8]
0bca9542  jnb 0x0bca0014	->1
0bca9548  movsd [rdx+0x18], xmm7
0bca954d  mov dword [rdx+0x4], 0xfffffff5
0bca9554  mov [rdx], eax
0bca9556  add rsp, +0x10
0bca955a  jmp 0x0bca9def
---- TRACE 70 stop -> 66
```

### 71: Refinement of trace 70?

Not sure what's going on here; the bytecode is the same but the IR
isn't.

```
---- TRACE 71 start 66/14 "portrange 0-6000":2
0004  . KPRI     2   1
0005  . RET1     2   2
0022  ISF          8
0023  JMP      9 => 0025
0025  ADDVN    3   3   0  ; 1
0026  MOV      0   7
0027  JMP      5 => 0003
0003  ISGE     0   1
0004  JMP      5 => 0028
0000  . . FUNCC               ; ffi.meta.__lt
0005  JLOOP    5  66
---- TRACE 71 IR
0001    num SLOAD  #4    PI
0002    num SLOAD  #5    PI
0003    p64 PVAL   #21 
0004    p64 PVAL   #100
0005    p64 PVAL   #105
0006  + cdt CNEWI  +181  0003
0007 }  cdt CNEWI  +183  0003
0008 }  cdt CNEWI  +181  0004
0009  + cdt CNEWI  +181  0005
0010 >  nil GCSTEP 
0011    num ADD    0001  +1  
0012 >  cdt SLOAD  #2    T
0013    u16 FLOAD  0012  cdata.ctypeid
0014 >  int EQ     0013  +181
0015    p64 FLOAD  0012  cdata.ptr
0016 >  p64 UGT    0015  0005
---- TRACE 71 mcode 269
0bca9371  mov r13, r15
0bca9374  mov r14, rbx
0bca9377  add rsp, -0x10
0bca937b  mov dword [0x40b934a0], 0x47
0bca9386  movsd [rsp+0x8], xmm7
0bca938c  movsd [rsp+0x10], xmm6
0bca9392  mov edi, [0x40b934ac]
0bca9399  mov esi, 0x10
0bca939e  call 0x0041f4e0	->lj_mem_newgco
0bca93a3  movzx ecx, byte [0x40b933e0]
0bca93ab  and ecx, +0x03
0bca93ae  or ecx, 0x00b50a00
0bca93b4  mov [rax+0x4], ecx
0bca93b7  mov [rax+0x8], r14
0bca93bb  mov r15d, eax
0bca93be  mov edi, [0x40b934ac]
0bca93c5  mov esi, 0x10
0bca93ca  call 0x0041f4e0	->lj_mem_newgco
0bca93cf  movzx ecx, byte [0x40b933e0]
0bca93d7  and ecx, +0x03
0bca93da  or ecx, 0x00b50a00
0bca93e0  mov [rax+0x4], ecx
0bca93e3  mov [rax+0x8], rbp
0bca93e7  mov [rsp+0x18], eax
0bca93eb  mov edi, [0x40b933d8]
0bca93f2  cmp edi, [0x40b933dc]
0bca93f9  jb 0x0bca9412
0bca93fb  mov esi, 0x2
0bca9400  mov edi, 0x40b933b8
0bca9405  call 0x0041f3d0	->lj_gc_step_jit
0bca940a  test eax, eax
0bca940c  jnz 0x0bca0010	->0
0bca9412  mov edx, [0x40b934b0]
0bca9419  mov eax, [rsp+0x18]
0bca941d  movsd xmm6, [rsp+0x10]
0bca9423  movsd xmm5, [rsp+0x8]
0bca9429  movsd xmm4, [0x419a2370]
0bca9432  movaps xmm7, xmm5
0bca9435  addsd xmm7, xmm4
0bca9439  cmp dword [rdx+0xc], -0x0b
0bca943d  jnz 0x0bca0010	->0
0bca9443  mov ebx, [rdx+0x8]
0bca9446  movzx r15d, word [rbx+0x6]
0bca944b  cmp r15d, 0xb5
0bca9452  jnz 0x0bca0014	->1
0bca9458  cmp rbp, [rbx+0x8]
0bca945c  jnb 0x0bca0014	->1
0bca9462  movsd [rdx+0x20], xmm6
0bca9467  movsd [rdx+0x18], xmm7
0bca946c  mov dword [rdx+0x4], 0xfffffff5
0bca9473  mov [rdx], eax
0bca9475  add rsp, +0x10
0bca9479  jmp 0x0bca9def
---- TRACE 71 stop -> 66
```
