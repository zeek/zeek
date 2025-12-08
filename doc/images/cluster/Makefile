# Needs svgbob_cli to regenerate SVG files (https://ivanceras.github.io/content/Svgbob.html)
SVGBOB=svgbob_cli

%.svg : %.txt
	$(SVGBOB) $< -o $@

all: single-system-one-nic.svg \
	single-system-two-nics.svg \
	three-systems-shared-pubsub.svg \
	three-systems-individual-pubsub.svg \
	single-system-prometheus.svg \
	single-system-websocket.svg
