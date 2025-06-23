from z3 import *

value_table = [
    (4, 146),
    (650, 97),
    (614, 77),
    (281, 32),
    (516, 64),
    (190, 32),
    (132, 45),
    (43, 57),
    (578, 64),
    (445, 17),
    (11, 18),
    (125, 17),
    (1, 147),
    (534, 77),
    (352, 16),
    (2, 82),
    (259, 96),
    (728, 211),
    (635, 61),
    (559, 64),
    (594, 83),
    (21, 35),
    (179, 83),
    (323, 130),
    (267, 64),
    (514, 17),
    (357, 49),
    (135, 34),
    (500, 48),
    (108, 227),
    (188, 194),
    (227, 36),
    (116, 17),
    (706, 115),
    (702, 2),
    (15, 66),
    (25, 82),
    (714, 178),
    (681, 33),
    (430, 203),
    (392, 147),
    (57, 32),
    (592, 211),
    (404, 18),
    (405, 211),
    (433, 33),
    (114, 49),
    (139, 33),
    (159, 56),
    (524, 48),
    (107, 82),
    (649, 49),
    (626, 64),
    (216, 243),
    (81, 210),
    (303, 16),
    (174, 113),
    (96, 49),
    (486, 194),
    (411, 163),
    (548, 17),
    (243, 115),
    (38, 60),
    (569, 17),
    (162, 2),
    (723, 3),
    (648, 178),
    (612, 33),
    (14, 227),
    (189, 35),
    (33, 33),
    (62, 33),
    (431, 114),
    (22, 195),
    (689, 147),
    (367, 36),
    (566, 226),
    (633, 96),
    (237, 81),
    (13, 147),
    (480, 96),
    (356, 48),
    (24, 178),
    (208, 33),
    (154, 37),
    (583, 32),
    (79, 53),
    (120, 48),
    (726, 226),
    (451, 89),
    (538, 57),
    (12, 194),
    (150, 210),
    (72, 115),
    (717, 210),
    (674, 66),
    (16, 211),
    (18, 131),
    (166, 48),
    (462, 53),
    (458, 19),
    (437, 33),
    (10, 82),
    (229, 64),
    (269, 227),
    (224, 179),
    (334, 16),
    (276, 48),
    (645, 57),
    (80, 2),
    (677, 49),
    (100, 57),
    (50, 214),
    (654, 49),
    (539, 18),
    (464, 33),
    (217, 33),
    (247, 33),
    (297, 147),
    (130, 1),
    (183, 77),
    (41, 57),
    (149, 146),
    (111, 163),
    (309, 195),
    (296, 162),
    (378, 210),
    (19, 147),
    (483, 16),
    (134, 82),
    (279, 33),
    (656, 41),
    (277, 2),
    (602, 40),
    (589, 15),
    (512, 18),
    (715, 99),
    (390, 40),
    (664, 1),
    (443, 49),
    (255, 114),
    (710, 162),
    (432, 195),
    (91, 40),
    (176, 66),
    (313, 35),
    (688, 130),
    (138, 16),
    (3, 19),
    (513, 82),
    (721, 66),
    (245, 61),
    (459, 34),
    (36, 115),
    (20, 19),
    (441, 211),
    (339, 53),
    (212, 96),
    (26, 243),
    (270, 19),
    (337, 36),
    (319, 16),
    (242, 98),
    (700, 44),
    (351, 2),
    (505, 108),
    (716, 19),
    (643, 52),
    (620, 82),
    (408, 138),
    (344, 88),
    (29, 17),
    (711, 242),
    (397, 55),
    (110, 80),
    (705, 51),
    (718, 115),
    (391, 66),
    (401, 94),
    (482, 37),
    (315, 128),
    (493, 51),
    (254, 16),
    (301, 17),
    (161, 98),
    (215, 146),
    (59, 33),
    (495, 52),
    (593, 66),
    (298, 17),
    (546, 59),
    (0, 179),
    (145, 33),
    (725, 147),
    (487, 49),
    (536, 77),
    (703, 130),
    (491, 77),
    (708, 66),
    (381, 16),
    (621, 67),
    (258, 43),
    (724, 226),
    (476, 32),
    (193, 49),
    (6, 35),
    (720, 179),
    (426, 32),
    (410, 36),
    (197, 0),
    (727, 66),
    (264, 37),
    (55, 163),
    (580, 129),
    (9, 18),
    (485, 35),
    (178, 64),
    (56, 49),
    (8, 211),
    (214, 61),
    (447, 17),
    (722, 114),
    (260, 81),
    (324, 243),
    (686, 33),
    (359, 80),
    (707, 178),
    (30, 0),
    (605, 50),
    (571, 32),
    (701, 210),
    (653, 64),
    (442, 81),
    (709, 115),
    (262, 49),
    (7, 98),
    (310, 18),
    (5, 210),
    (422, 17),
    (388, 81),
    (719, 83),
    (295, 32),
    (704, 210),
    (529, 73),
    (540, 67),
    (192, 17),
    (712, 114),
    (54, 211),
    (375, 69),
    (53, 211),
    (27, 211),
    (46, 57),
    (23, 18),
    (551, 65),
    (713, 226),
    (165, 33),
    (112, 65),
    (282, 211),
    (675, 66),
    (169, 64),
    (440, 32),
    (573, 49),
    (17, 99),
    (567, 115),
    (228, 210),
    (222, 81),
    (631, 41),
    (647, 130),
    (66, 243),
    (377, 179),
    (525, 146),
    (350, 211),
    (667, 118),
]

def all_boxes():
    for x0 in [0, 1]:
        for x1 in [0, 1]:
            for x2 in [0, 1]:
                for x3 in [0, 1]:
                    for x4 in [0, 1]:
                        for x5 in [0, 1]:
                            for x6 in [0, 1]:
                                for x7 in [0, 1]:
                                    yield [x0, x1, x2, x3, x4, x5, x6, x7]
    
def check1(box, expected):
    if expected & 0xfffffff7 == 0: return True
    box = box+[]
    x0 = box[0]
    x1 = box[1]
    x2 = box[2]
    x3 = box[3]
    x4 = box[4]
    x5 = box[5]
    x6 = box[6]
    x7 = box[7]
    
    if (x0 == 0):
        while x0 == 0:
            rax = x0
            x0 = x7
            x7 = x6
            x6 = x5
            x5 = x4
            x4 = x3
            x3 = x2
            x2 = x1
            x1 = rax
        box[0] = x0;
        box[1] = rax;
        box[2] = x2;
        box[3] = x3;
        box[4] = x4;
        box[5] = x5;
        box[6] = x6;
        box[7] = x7;

    if (x7 == 1):
        while x7 == 1:
            rax = x0
            x0 = x7
            x7 = x6
            x6 = x5
            x5 = x4
            x4 = x3
            x3 = x2
            x2 = x1
            x1 = rax
        box[0] = x0;
        box[1] = rax;
        box[2] = x2;
        box[3] = x3;
        box[4] = x4;
        box[5] = x5;
        box[6] = x6;
        box[7] = x7;
        

    i = 0
    while box[i] != 0:
        i+=1
        if i>=8:
            break
            
    if expected != -1:
        return i == expected
        
    for j in range(i, 8):
        if box[j] == 1:
            return False
            
    return True
    
def check1_z3(arr, offset, expected):

    box2 = [None]*8
    box2[0] = arr[offset - 1];
    box2[1] = arr[offset + 0x1a];
    box2[2] = arr[offset + 0x1b];
    box2[3] = arr[offset + 0x1c];
    box2[4] = arr[offset + 1];
    box2[5] = arr[offset - 0x1a];
    box2[6] = arr[offset - 0x1b];
    box2[7] = arr[offset - 0x1c];
            
    bc = []
    for box in all_boxes():
        if len(set(box)) > 1 and check1(box, expected):
            bc.append(And([box2[i] == box[i] for i in range(8)]))
    
    return Or(bc)
    
    
def check2_z3(arr, offset, expected):
    box2 = [None]*8
    box2[0] = arr[offset - 1];
    box2[1] = arr[offset + 0x1a];
    box2[2] = arr[offset + 0x1b];
    box2[3] = arr[offset + 0x1c];
    box2[4] = arr[offset + 1];
    box2[5] = arr[offset - 0x1a];
    box2[6] = arr[offset - 0x1b];
    box2[7] = arr[offset - 0x1c];
            
    bc = []
    for box in all_boxes():
        if check2(box, expected):
            bc.append(And([box2[i] == box[i] for i in range(8)]))
    return (Or(bc))
    

def check2(box, expected):
    if expected > 4: return False

    for i in range(8):
        if box[i] == 1:
            if (box[(i+1)%8] == 0x1): 
                return False
            if (box[(i-1)%8] == 0x1):
                return False

    return True


solver = Solver()
arr = [BitVec("v_"+str(i), 1) for i in range(729)]
for i in range(len(arr)):
    solver.add(Or(arr[i] == 0, arr[i] == 1))

for offset, mask in value_table:
    if mask&2:
        expected_value = -1
    else:
        expected_value = (mask>>4)&0xf
   
    if mask&8:
        if not mask&4:
            solver.add(check1_z3(arr, offset, expected_value))
        else:
            solver.add(Or(check2_z3(arr, offset, expected_value), check1_z3(arr, offset, expected_value)))
    elif mask&4:
        solver.add(check2_z3(arr, offset, expected_value))

    if expected_value != -1:
        sumthis = [arr[offset + i] for i in [-0x1C, 0x1C, -0x1B, 0x1B, -0x1A, 0x1A, -1, 1]]
        solver.add(Sum([ZeroExt(15, a) for a in sumthis]) == expected_value)
    solver.add(arr[offset] == 0)


solver.add(Sum([ZeroExt(15, a) for a in arr]) == 179)

while solver.check() == sat:
    m = solver.model()
    
    out = ""
    for i in range(len(arr)):
        out += chr(m[arr[i]].as_long()+0x30)
    print(out)
    
    solver.add(Or([arr[i] != m[arr[i]] for i in range(len(arr))]))
    
print("done")