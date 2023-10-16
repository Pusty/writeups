def swap(shuffle, a, xorStuff, m):
    tmp = shuffle[a] 
    shuffle[a] = shuffle[xorStuff%m]
    shuffle[xorStuff%m] = tmp
           
   
def shuffeArray(gameIndex, iterationIndex, seed):
    shuffle = [i for i in range(13)]
    xorStuff = gameIndex^seed^iterationIndex

    for i in range(12, 0, -1):
        swap(shuffle, i, xorStuff, i+1)
    return shuffle
        
spookyArray = [
    "*OoooOOOoooo*",
    "*Booooo-hoooo*",
    "*Eeeeek*",
    "*Hoooowl*",
    "*Sliiither*",
    "*Waaail*",
    "*Woooosh*",
    "*Eeeerie*",
    "*Creeeeeeak*",
    "*Haauuunt*",
    "*Woooo-woooo*",
    "*Gaaaasp*",
    "*Shiiivver*"
]


def getEnemyTurn(msg, iterationIndex, gameIndex, seed):
    shuffle = shuffeArray(gameIndex, iterationIndex, seed)
    unshuffle = [0 for _ in range(0xd)]
    for i in range(0xd):
        unshuffle[shuffle[i]] = i
        
    unspookyMap = {}

    for i in range(len(spookyArray)):
        unspookyMap[spookyArray[i]] = unshuffle[i]

    return unspookyMap[msg]

TILE_EMPTY = 0
TILE_PLAYER = 1
TILE_ENEMY = -1

def actions(state):
    return [i for i in range(len(state)) if state[i] == TILE_EMPTY]

def won(state):
    for i in range(3):
        if state[i*3] != TILE_EMPTY and state[i*3] == state[i*3+1] and state[i*3+1] == state[i*3+2]:
            return state[i*3]
        if state[i] != TILE_EMPTY and state[i] == state[i+3] and state[i+3] == state[i+6]:
            return state[i]

    if state[0] != TILE_EMPTY and state[0] == state[4] and state[4] == state[8]:
        return state[0]
    if state[2] != TILE_EMPTY and state[2] == state[4] and state[4] ==  state[6]:
        return state[2]

    if not TILE_EMPTY in state:
        return 0

    return None

    
def checkMoves(state, maxormin, player, depth, choice=None):
    term = won(state)
    if term == 0:
        return (0, choice)
    elif term == TILE_PLAYER:
        return (10 - depth, choice)
    elif term == TILE_ENEMY:
        return (-10 + depth, choice)
        
        
    moves = actions(state)
    solutions = []
    for move in moves:
        stateCopy = state.copy()
        stateCopy[move] = player
        c = checkMoves(stateCopy, not maxormin, -player, depth+1, move if choice == None else choice)
        solutions.append(c)


    maxChoice = None
    maxScore  = -11
    minChoice = None
    minScore  = 11
    
    for (score, choice) in solutions:
        if score > maxScore:
            maxChoice = (score, choice)
            maxScore = score
        if score < minScore:
            minChoice = (score, choice)
            minScore = score

    return maxChoice if maxormin else minChoice
        
def findMove(state, gameIndex):
    return checkMoves(state, True, TILE_PLAYER, 0)[1]
        

def printTicTacTo(state):
    charMap = {TILE_EMPTY:" ", TILE_PLAYER: "X", TILE_ENEMY: "O"}
    for i in range(3):
        print(''.join([charMap[state[i*3+j]] for j in range(3)]))
    
    

amounOfRounds = 50


from pwn import *        

#p = remote('flu.xxx', 10140)
p = process(['./ghost_no_flag', str(amounOfRounds), '1'])
p.recvuntil(b'       |')
seed = int(p.recvline().decode("ascii").strip(), 10)

startsFirst = True

for gameIndex in range(amounOfRounds):
    print("================ GAME START =================")
    p.recvuntil(b'13) Lumina Exordium')

    tictactoe = [TILE_EMPTY]*9
    
    roundIndex = 0
    if startsFirst:
        tictactoe[4] = TILE_PLAYER
        p.sendline(b'5')
        roundIndex = roundIndex + 1
        printTicTacTo(tictactoe)

    while won(tictactoe) == None:
        p.recvuntil(b'       |  *')
        ghostSay = (b'*'+p.recvline()).decode("ascii").strip()
        print(ghostSay)
        enemyTurn = getEnemyTurn(ghostSay, roundIndex, gameIndex, seed)
        tictactoe[enemyTurn]= TILE_ENEMY
        roundIndex = roundIndex + 1
        printTicTacTo(tictactoe)
        if won(tictactoe) != None:
            startsFirst = True
            break
        nextMove = findMove(tictactoe, gameIndex)
        tictactoe[nextMove] = TILE_PLAYER
        p.sendline(str(nextMove+1).encode("ascii"))
        roundIndex = roundIndex + 1
        printTicTacTo(tictactoe)
        startsFirst = False

p.interactive()