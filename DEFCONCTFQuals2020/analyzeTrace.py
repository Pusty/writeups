trace = open("trace.txt")

lines = trace.read()
trace.close()

treeStruct = None

currentNode = None

index = -1
prevLine = ""
indend = ""


stackPush = []

for line in lines.split("\n"):
    if line.startswith("efc8a8dc3f15ba2148e098df4c2d2db4"):
        print("\nCharacter start:")
        indend = ""
        index = index + 1
        
    if line.startswith("d670e25f0b1e4b298321e687f777ec14"):
        print(indend+"linkedList!")
        indend = indend + "  "
        
    if line.startswith("b58310a1d83b616fca1491b8ddaa4051"):
        print(indend+"Create new node")
        stackPush.append(None)
        currentNode = [["c"+str(index)], 1, 1, None, None]
        
    if line.startswith("b39fabb14ca48dfa222944f6b24fff4b"):
        print(indend+"c == l->character, value1++")
        stackPush.append(None)
        currentNode[1] += 1
        currentNode[0].append("c"+str(index))
        
    if line.startswith("c622d85d8eac36de71a2da9b7c141eec"):
        print(indend+"c < l->character, l->p2")
        stackPush.append((currentNode, 3))
        currentNode = currentNode[3]
        
    if line.startswith("5f694f9d4d0ea82638f21bae6503ee8c"):
        print(indend+"c > l->character, l->p1")
        stackPush.append((currentNode, 4))
        currentNode = currentNode[4]
        
    if line.startswith("de1f054aea218ff74c8b2832814a3009"):
        if len(stackPush) > 0:
            p = stackPush.pop()
            if p == None and len(stackPush) > 0:
                p = stackPush.pop()
            if p != None:
                n = p[0]
                n[p[1]] = currentNode
                currentNode = n
        print(indend+"return")
        indend = indend[2:]
        
        
    if line.startswith("40e0f0d7c4a81e18cc330857a716b6b0") and prevLine.startswith("cdd8d0db80a1e08e0b2f480d2437b45d"):
        print(indend+"l->p2 == 0")
        
    if line.startswith("40e0f0d7c4a81e18cc330857a716b6b0") and prevLine.startswith("1d3cd83339084286a1100abe18df6cc3"):
        print(indend+"l->p2->p2 == 0")
        
    if line.startswith("40e0f0d7c4a81e18cc330857a716b6b0") and prevLine.startswith("df94ae98b0d0af748ec2d249182b86b0"):
        print(indend+"l->p2->p2->value2 != l->value2")
        
    if line.startswith("57c4fb55862a54ce50f667af48b390e7"):
        print(indend+"modify2!, value2++")
        n = currentNode[4]
        currentNode[4] = n[3]
        n[3] = currentNode
        n[2] += 1
        currentNode = n
        
    if line.startswith("3f22294678ad1d8370ac9af2a3313c8f") and prevLine.startswith("82d0a15c53505f9cbe99f6d72683ce27"):
        print(indend+"l->p1 == 0")
        
    if line.startswith("3f22294678ad1d8370ac9af2a3313c8f") and prevLine.startswith("98d38856414f65c192bbf00f01e1a835"):
        print(indend+"l->p1->value2 != l->value2")

    if line.startswith("eeef3e11294110f840d4fc0a1273c089"):
        print(indend+"modify1!")
        n = currentNode[3]
        currentNode[3] = n[4]
        n[4] = currentNode
        currentNode = n
    
        
    prevLine = line
    
print(currentNode)

def pTree(n):
    a = []
    if n[3] != None:
        a = a + pTree(n[3])
    a = a + [n[0]]
    if n[4] != None:
        a = a + pTree(n[4])
    return a

print(pTree(currentNode))
    