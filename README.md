# data-ptr-comm
communicate between usermode and kernelmode through a qword ptr argument

used to bypass game anti-cheats like easyanticheat and battleye

### notes
tested on win ver 21h2

i'm not sure if this is undetected as i chain different pointers (which i have deleted), so chaining might be a good idea

### the function
NtUserSetGestureConfig in win32k.sys

pseudocode
```cpp
__int64 (__fastcall *__fastcall NtUserSetGestureConfig(__int64 a1))(_QWORD)
{
  __int64 (__fastcall *result)(_QWORD); // rax

  result = qword_FFFFF97FFF065648;
  if ( qword_FFFFF97FFF065648 )
    return (__int64 (__fastcall *)(_QWORD))qword_FFFFF97FFF065648(a1);
  return result;
}
```
assembly
```sh
sub     rsp, 38h
mov     rax, cs:qword_FFFFF97FFF065648 <-- our qword, signature created here
test    rax, rax
jz      short loc_FFFFF97FFF007DC0
```
