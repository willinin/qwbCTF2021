# Readme

qwbCTF 2021 notebook 的两种解法，分别是go.c和go1.c。

没有用 userfaultfd去注册回调函数，事先不知道这个知识点。 事先也不知道heap harden。依靠着暴力竞争实现的uaf。

userfaultfd和 one  gadget -> two gadget ->rop 的板子几乎必备。

最后，从源码上我没看出kmalloc和krealloc的区别，但是根据调试情况来看，krealloc不会从freelist这个链上取freed的堆块，或者说取的链不一样？在go1.c的最后将add换成edit是永远成功不了的。存疑留个档。

