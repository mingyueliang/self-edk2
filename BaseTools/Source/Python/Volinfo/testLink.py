# mlist = None
#
# class Node():
#     def __init__(self, item):
#         self.item = item
#         self.next = None
#
#
# def create_linklist_head():
#     global mlist
#     for i in range(5):
#         node = Node(i)
#         node.next = mlist
#         mlist = node
#
# def printlink():
#     global mlist
#     create_linklist_head()
#     while mlist:
#         print(mlist.item, ',')
#         mlist = mlist.next

# printlink()

# print("Header Length: ".ljust(20) , "ffffffffffffffffffffff")
# print("Header Lth: ".ljust(20) , "ffffff")
# print("Header : ".ljust(20) , "ffffffffff")
# print("Header Length: ".ljust(20) , "ffffffffffffff")
# print("Header: ".ljust(20) , "ffffffffffffffff")



class Shape: # 基类(雪人各部件（形状）共有的属性)
    def __init__(self, cvns, points, fill): # 构造方法 画布 位置坐标 颜色
        self.cvns = cvns # 画布
        self.points = points # 坐标（x1, y1, x2, y2）
        self.fill = fill
        self.pid = None # 当前图形的id
    def delete(self): # 删除图形
        if self.pid:
            self.cvns.delete(self.pid)
class ShapeAngles(Shape): # 继承基类(增加了角度）)
    def __init__(self, cvns, points, fill, angles=(10, 170)): # angles:角度值,带默认参数
        super(ShapeAngles, self).__init__(cvns, points, fill) # 调用基类构造: cvns,points,fill
        self.angles = {'start':angles[0], 'extent':angles[1]} # 构造自己的属性：angles
class HatTop(Shape): # 帽子顶部
    def draw(self):
        # self.pid = self.cvns.create_oval(self.points, fill='white') # 椭圆形
        self.pid = self.cvns.create_oval(self.points, fill=self.fill) # 椭圆形
class HatBottom(Shape): # 帽子底部
    def draw(self):
        self.p