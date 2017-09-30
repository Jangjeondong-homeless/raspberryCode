import os, io, csv, codecs
directory = os.listdir('signatures')
os.chdir('signatures')
sidout = codecs.open("../sid.tsv", "w", encoding='utf-8')
wr = csv.writer(sidout, delimiter='\t')

for file in directory:
    sid = open(file, 'r')
    data = sid.readlines()
    delimiter = '--\n'
    columnPosition = []
    index = 0
    aaa=[]
    for line in data:
        if line == delimiter:
            columnPosition.append(index)
        index += 1

    colPair = []
    tempPair = []
    for x in columnPosition :
        tempPair.append(x)
        if len(tempPair) == 2:
            colPair.append(tempPair)
            tempPair = [x]

    result = ''
    wrlist = []

    for x in colPair:
        content = ''
        for y in range(x[0]+2, x[1]):
            content += data[y]
        contentLen = len(content)
        content = content[:contentLen-2]
        wrlist.append(content)

    CVEIndex = wrlist[-1].find('CVE')
    CVEEnd = CVEIndex
    if CVEIndex > 0:
        for x in range(CVEIndex, CVEIndex+20):
            CVEEnd += 1
            if wrlist[-1][x] == ':':
                break
        wrlist.append(wrlist[-1][CVEIndex:CVEEnd-1])
    wr.writerow(wrlist)

    print(wrlist)

    sid.close()
sidout.close()