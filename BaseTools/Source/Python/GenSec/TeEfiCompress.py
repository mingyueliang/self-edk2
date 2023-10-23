p = int(input("Please Type number: "))
c = 0
while p:
    p >>= 1
    c += 1

print("c = ", c)