.code
getPEB proc
	     mov rax, gs:[60h] ;PEB
		 ret
getPEB endp

PEBPatcher proc
			xor eax,eax
			call getPEB
			movzx eax,byte ptr [rax+2h];PEB->Being Debugged
			test eax,eax
			jnz PATCH
			ret

PATCH:
		xor eax,eax
		call getPEB
		mov byte ptr [rax+2h],0
		ret

PEBPatcher endp

end