"""Permite arrancar el menú con `python -m analizador`."""

from .cli import main

# Propaga al sistema el código de salida devuelto por el menú.
raise SystemExit(main())
