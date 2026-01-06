CC = gcc
LDFLAGS = -I. -ldl -lpthread -lm
ifeq ($(build),release)
	CFLAGS = -O3
	LDFLAGS += -DNDEBUG=1
else
	CFLAGS = -Og -g
endif
CFLAGS += -std=gnu89 -Wall -Wextra -Werror -pedantic
RM = rm -rf

OBJECTS = aes_gcm.o
OBJECTS := $(addprefix objects/,$(OBJECTS))
EXECUTABLE = aes_gcm

all: objects $(EXECUTABLE)

objects:
	@echo "Create 'objects' folder ..."
	@mkdir -p objects

$(EXECUTABLE): objects/main.o $(OBJECTS)
ifeq ($(build),release)
	@echo "Build release '$@' executable ..."
else
	@echo "Build '$@' executable ..."
endif
	@$(CC) objects/main.o $(OBJECTS) -o $@ $(LDFLAGS)
	@$(RM) objects/main.o

demo: objects/demo.o $(OBJECTS)
ifeq ($(build),release)
	@echo "Build release '$@' executable ..."
else
	@echo "Build '$@' executable ..."
endif
	@$(CC) objects/demo.o $(OBJECTS) -o $@ $(LDFLAGS)
	@$(RM) objects/demo.o

objects/%.o: %.c
ifeq ($(build),release)
	@echo "Build release '$@' object ..."
else
	@echo "Build '$@' object ..."
endif
	@$(CC) -c $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	@echo "Cleanup ..."
	@$(RM) $(OBJECTS) $(EXECUTABLE) demo
