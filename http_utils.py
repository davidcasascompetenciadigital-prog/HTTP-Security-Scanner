#!/usr/bin/env python3
"""
Utilidades compartidas para el análisis de cabeceras y cookies HTTP

Autor: David Casas M. - Competencia Digital
Licencia: CC BY-NC 4.0
"""


def is_httponly(cookie) -> bool:
    """
    Indica si una cookie tiene el flag HttpOnly.

    Importante: requests almacena el atributo con mayúscula inicial ('HttpOnly'),
    por lo que consultar 'httponly' en minúsculas devuelve siempre False.
    """
    return (cookie.has_nonstandard_attr('HttpOnly') or
            cookie.has_nonstandard_attr('httponly'))


def get_samesite(cookie) -> str:
    """
    Devuelve el valor del atributo SameSite de una cookie.

    Devuelve 'None' si la cookie no declara SameSite.
    """
    value = cookie.get_nonstandard_attr('SameSite')
    if value is None:
        value = cookie.get_nonstandard_attr('samesite')
    return value if value else 'None'
