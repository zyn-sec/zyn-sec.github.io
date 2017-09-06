## Welcome to zyn-sec.io

This is the space for the real CTF's challenges write ups. Here's the list.

[BCTF 2017-Babyuse / Use-After-Free](https://zyn-sec.github.io/BCTF-Babyuse)
	
 - 多次利用UAF泄露堆内地址和libc中地址
 - 根据free的调用顺序和chunk大小构建需要的fastbin free list
 - 构建伪造的vtable并根据上一步的list放到确定的地址

[0CTF 2017-Babyheap / Fastbin-dup](https://zyn-sec.github.io/0CTF-Babyheap)

 - 如果出现简单的堆溢出，则可以直接修改fastbin free list中的顺序，甚至直接将还在使用的chunk放到里面
 - 修改list的时候同时需要伪造chunk的大小
 - ？？？问题：泄露出来地址之后我们应当把shell放到哪里？
 - ？？？问题：_malloc_hook_的大小如何控制？
