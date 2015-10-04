/* aes_enc-asm.S */
/*
    This file is part of the AVR-Crypto-Lib.
    Copyright (C) 2006-2015 Daniel Otte (daniel.otte@rub.de)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


	.syntax unified
	.cpu cortex-m0
	.thumb

.global qxtimes
qxtimes:
	push {r1, r2, lr}
	ldr r2, =0x80808080
	ands r2, r2, r0
	ldr r1, =0xfefefefe
	lsls r0, r0, #1
	ands r0, r0, r1
	lsrs r2, r2, #3
	eors r0, r0, r2
	lsrs r2, r2, #1
	eors r0, r0, r2
	lsrs r2, r2, #2
	eors r0, r0, r2
	lsrs r2, r2, #1
	eors r0, r0, r2
	pop {r1, r2, pc}


.global sbox
sbox:
	ldr r1, =aes_sbox
	ldr r2, =16
1:
	subs r2, r2, #1
	ldrb r3, [r0, r2]
	ldrb r3, [r1, r3]
	strb r3, [r0, r2]
	bne 1b
	bx lr

.global convert
convert:
	ldr r3, =4
1:
	ldrb r2, [r1, #0]
	strb r2, [r0, #0]
	ldrb r2, [r1, #1]
	strb r2, [r0, #4]
	ldrb r2, [r1, #2]
	strb r2, [r0, #8]
	ldrb r2, [r1, #3]
	strb r2, [r0, #12]
	adds r1, r1, #4
	adds r0, r0, #1
	subs r3, r3, #1
	bne 1b
	bx lr

.global key_xor
key_xor:
	push {r4, lr}
	ldr r4, =4
1:
	ldrb r2, [r1, #0]
	ldrb r3, [r0, #0]
	eors r2, r2, r3
	strb r2, [r0, #0]
	ldrb r2, [r1, #1]
	ldrb r3, [r0, #4]
	eors r2, r2, r3
	strb r2, [r0, #4]
	ldrb r2, [r1, #2]
	ldrb r3, [r0, #8]
	eors r2, r2, r3
	strb r2, [r0, #8]
	ldrb r2, [r1, #3]
	ldrb r3, [r0, #12]
	eors r2, r2, r3
	strb r2, [r0, #12]
	adds r1, r1, #4
	adds r0, r0, #1
	subs r4, r4, #1
	bne 1b
	pop {r4, pc}

/*
void mixColums(new_aes_state_t *x){
    uint32_t tm, tmp, v;
    v = x->a[0];
    tmp = x->a[0] ^ x->a[1] ^ x->a[2] ^ x->a[3];

    tm = qxtimes(x->a[0] ^ x->a[1]);
    x->a[0] ^= tm ^ tmp;

    tm = qxtimes(x->a[1] ^ x->a[2]);
    x->a[1] ^= tm ^ tmp;

    tm = qxtimes(x->a[2] ^ x->a[3]);
    x->a[2] ^= tm ^ tmp;

    tm = qxtimes(x->a[3] ^ v);
    x->a[3] ^= tm ^ tmp;
}
*/
tm  .req r0
tmp .req r1
z   .req r2
.global aes_enc_round
aes_enc_round:
	push {r0, r1, v1, v2, v3, v4, lr}
	bl sbox
	ldm r0!, {v1, v2, v3, v4}
	ldr r0, =8
	rors v2, v2, r0
	adds r0, r0, #8
	rors v3, v3, r0
	adds r0, r0, #8
	rors v4, v4, r0
	movs z, v1
	movs tmp, v1
	eors tmp, tmp, v2
	movs tm, tmp
	eors tmp, tmp, v3
	eors tmp, tmp, v4

	bl qxtimes
	eors v1, v1, tm
	eors v1, v1, tmp

	movs tm, v2
	eors tm, v3
	bl qxtimes
	eors v2, v2, tm
	eors v2, v2, tmp

	movs tm, v3
	eors tm, v4
	bl qxtimes
	eors v3, v3, tm
	eors v3, v3, tmp

	movs tm, v4
	eors tm, z
	bl qxtimes
	eors v4, v4, tm
	eors v4, v4, tmp

	pop {r0}
	stm r0!, {v1, v2, v3, v4}
	subs r0, r0, #16
	pop {r1, v1, v2, v3, v4}
	bl key_xor
	pop {pc}



