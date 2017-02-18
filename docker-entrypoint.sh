#!/bin/sh

/app/fiche -o /data -d ${FCH_DOMAIN:-localhost} -s ${FCH_SLUG:-4} -B ${FCH_BUFFERSIZE:-4096} -l /dev/stdout
