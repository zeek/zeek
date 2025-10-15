MMDC?=./node_modules/.bin/mmdc

%.png : %.mermaid
	$(MMDC) -i $< -e png -o $@

all: zeromq-cluster.png zeromq-pubsub.png zeromq-logging.png
