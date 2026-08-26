"""Application services: the operations behind the routes and the CLI.

Routes translate HTTP into arguments and results into responses; everything
that decides *what happens* lives here, so the same operation can be driven
from the web UI, the REST API (M5) and the command line without three
implementations drifting apart.
"""
