import sys

def composeIfElses(infile, outfile, insym, outsym):
    first = True
    with open(infile, 'r') as fi, open(outfile, 'w') as fo:
        line = fi.readline()
        while line:
            if (first):
                write_if(line, fo, insym, outsym)
            else:
                write_elif(line, fo, insym, outsym)
            line = fi.readline()
            first = False

def write_if(line, f, insym, outsym):
    name, value = line.split()
    f.write("if("+insym+"=="+value+"){\n")
    f.write("\t"+outsym+"=\""+name+"\";\n")
    f.write("}")

def write_elif(line, f, insym, outsym):
    name, value = line.split()
    f.write("else if("+insym+"=="+value+"){\n")
    f.write("\t"+outsym+"=\""+name+"\";\n")
    f.write("}")

if __name__ == '__main__':
    for i in sys.argv:
        print(i)
    _, infile, outfile, insym, outsym = sys.argv 
    composeIfElses(infile, outfile, insym, outsym)
