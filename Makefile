Object = analysisPcap.o common.o hash.o readPcap.o taskCounterBraids.o testCounterBraids.o
EXE = test

test: $(Object)
	gcc -o $(EXE) $(Object)

analysisPcap.o: analysisPcap.c analysisPcap.h common.h
	gcc -c analysisPcap.c

hash.o: hash.c hash.h common.h
	gcc -c hash.c

common.o: common.c common.h
	gcc -c common.c

readPcap.o: readPcap.c readPcap.h common.h
	gcc -c readPcap.c

taskCounterBraids.o: taskCounterBraids.c taskCounterBraids.h common.h hash.h
	gcc -c taskCounterBraids.c

testCounterBraids.o: testCounterBraids.c common.h hash.h analysisPcap.h taskCounterBraids.h readPcap.h
	gcc -c testCounterBraids.c

clean:
	rm $(EXE) $(Object)
