# -*- coding: utf-8 -*-
# @Time : 12/27/2021 2:56 PM
# @Author : mliang2x
# @Email : mingyuex.liang@intel.com
# @File : HuffManTree.py
# @Project : GitHub_edk2

from tqdm import tqdm


def int_to_bytes(n: int) -> bytes:
    return bytes([n])


class HuffManNode(object):
    """HuffMan Node"""
    def __init__(self, value, freq, left_child, right_child):
        self.value = value
        self.weight = freq
        self.left_child = left_child
        self.right_child = right_child


class HuffManTree(object):
    @staticmethod
    def bytes_fre(bytes_buffer: bytes):
        """
        Count the frequency of characters
        return: freq dict
        """
        fre_dic = {_ : 0 for _ in range(256)}
        for item in bytes_buffer:
            fre_dic[item] += 1
        return {int_to_bytes(x): fre_dic[x] for x in range(256) if
                fre_dic[x] != 0}

    @staticmethod
    def build(fre_dic):

        def dlr(current, huffman_code, _huffman_dic):
            if current is None:
                return
            else:
                if current.left_child is None and current.right_child is None:
                    _huffman_dic[current.value] = huffman_code
                else:
                    dlr(current.left_child, huffman_code + '0', _huffman_dic)
                    dlr(current.right_child, huffman_code + '1', _huffman_dic)

        if not fre_dic:
            return {}
        elif len(fre_dic) == 1:
            return {value: '0' for value in fre_dic.keys()}

        # Init Huffman tree
        NodeList = [HuffManNode(value, weight, None, None) for value, weight in fre_dic.items()]
        # Build Huffman tree
        while len(NodeList) > 1:
            NodeList.sort(key=lambda item: item.weight, reverse=True)
            node1 = NodeList.pop()
            node2 = NodeList.pop()
            node_add = HuffManNode(None, node1.weight + node2.weight, node1, node2)
            NodeList.append(node_add)

        # Get Huffman coding table
        HuffmanDict = {key:'' for key in fre_dic.keys()}
        dlr(NodeList[0], '', HuffmanDict)
        return HuffmanDict

    @classmethod
    def to_canonical(cls, huffman_dic):
        """将Huffman编码转换成范氏Huffman编码"""
        code_lst = [(value, len(code)) for value, code in huffman_dic.items()]
        code_lst.sort(key=lambda item: (item[1], item[0]), reverse=False)
        value_lst, length_lst = [], []
        for value, length in code_lst:
            value_lst.append(value)
            length_lst.append(length)
        return cls.rebuild(value_lst, length_lst)

    @staticmethod
    def rebuild(char_lst, length_lst):
        """以范氏Huffman的形式恢复字典"""
        huffman_dic = {value: '' for value in char_lst}
        current_code = 0
        for i in range(len(char_lst)):
            if i == 0:
                current_code = 0
            else:
                current_code = (current_code + 1) << (
                            length_lst[i] - length_lst[i - 1])
            huffman_dic[char_lst[i]] = bin(current_code)[2::].rjust(
                length_lst[i], '0')
        return huffman_dic

    @staticmethod
    def decode(str_bytes: bytes, huffman_dic, padding: int,
               visualize: bool = False):
        """Huffman解码
        输入待编码文本, Huffman字典huffman_dic, 末端填充位padding
        返回编码后的文本
        """
        if not huffman_dic:  # 空字典，直接返回
            return b''
        elif len(huffman_dic) == 1:  # 字典长度为1，添加冗余结点，使之后续能够正常构建码树
            huffman_dic[b'OVO'] = 'OVO'
        # 初始化森林, 短码在前，长码在后, 长度相等的码字典序小的在前
        node_lst = [HuffManNode(value, weight, None, None) for value, weight in
                    huffman_dic.items()]
        node_lst.sort(key=lambda _item: (len(_item.weight), _item.weight),
                      reverse=False)
        # 构建Huffman树
        while len(node_lst) > 1:
            # 合并最后两棵树
            node_2 = node_lst.pop()
            node_1 = node_lst.pop()
            node_add = HuffManNode(None, node_1.weight[:-1:], node_1, node_2)
            node_lst.append(node_add)
            # 调整森林
            node_lst.sort(key=lambda _item: (len(_item.weight), _item.weight),
                          reverse=False)
        # 解密文本
        read_buffer, buffer_size = [], 0
        # 生成字符->二进制列表的映射
        dic = [list(map(int, bin(item)[2::].rjust(8, '0'))) for item in
               range(256)]
        # 将str_bytes转化为二进制列表
        for item in str_bytes:
            read_buffer.extend(dic[item])
            buffer_size = buffer_size + 8
        read_buffer = read_buffer[0: buffer_size - padding:]
        buffer_size = buffer_size - padding
        write_buffer = bytearray([])

        current = node_lst[0]

        for pos in tqdm(range(0, buffer_size, 8), unit='byte',
                        disable=not visualize):
            for item in read_buffer[pos:pos + 8]:
                # 根据二进制数移动current
                if item:
                    current = current.right_child
                else:
                    current = current.left_child
                # 到达叶结点，打印字符并重置current
                if current.left_child is None and current.right_child is None:
                    write_buffer.extend(current.value)
                    current = node_lst[0]

        return bytes(write_buffer)

    @staticmethod
    def encode(str_bytes: bytes, huffman_dic, visualize: bool = False):
        """Huffman编码
        输入待编码文本, Huffman字典huffman_dic
        返回末端填充位数padding和编码后的文本
        """
        bin_buffer = ''
        padding = 0
        # 生成整数->bytes的字典
        dic = [int_to_bytes(item) for item in range(256)]
        # 将bytes字符串转化成bytes列表
        read_buffer = [dic[item] for item in str_bytes]
        write_buffer = bytearray([])
        # 循环读入数据，同时编码输出
        for item in tqdm(read_buffer, unit='byte', disable=not visualize):
            bin_buffer = bin_buffer + huffman_dic[item]
            while len(bin_buffer) >= 8:
                write_buffer.append(int(bin_buffer[:8:], 2))
                bin_buffer = bin_buffer[8::]

        # 将缓冲区内的数据填充后输出
        if bin_buffer:
            padding = 8 - len(bin_buffer)
            bin_buffer = bin_buffer.ljust(8, '0')
            write_buffer.append(int(bin_buffer, 2))

        return bytes(write_buffer), padding



