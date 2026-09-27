#!/usr/bin/env python3
"""LLOGREFERENCE1A: scalar reference math, not an SL3-P camera renderer.

Independent implementation of Leica L-Log Reference Manual V1.9 equations 1/2
and BT.2020 / D65 coordinates. Source:
https://leica-camera.com/sites/default/files/pm-37826-L-Log_Reference_Manual_V1.9.pdf

Inputs must already be correctly calibrated, scene-linear, D65-adapted XYZ or
linear BT.2020 RGB, with an explicit scene-reflection scale. Neither raw sensor
normalization nor an inverse of a phone's tone-mapped video is implemented.
No Pure/Cine LUT, tone/gamut mapping, automatic exposure, codec level mapping,
spatial filtering or temporal processing is hidden here. Values are unclamped.
The published rounded constants produce a small branch discontinuity; this
reference retains it rather than silently inventing a modified Leica curve.
"""
from __future__ import annotations
import math
from typing import Sequence

RGB2020_TO_XYZ_D65 = (
    (0.6369580483012914, 0.1446169035862083, 0.1688809751641721),
    (0.2627002120112671, 0.6779980715188708, 0.0593017164698620),
    (0.0, 0.0280726930490874, 1.0609850577107910),
)
XYZ_D65_TO_RGB2020 = (
    (1.7166511879712674, -0.3556707837763924, -0.2533662813736597),
    (-0.6666843518324890, 1.6164812366349395, 0.0157685458139111),
    (0.0176398574453108, -0.0427706132578085, 0.9421031212354738),
)


def finite(value: float) -> float:
    value = float(value)
    if not math.isfinite(value):
        raise ValueError('Input must be finite')
    return value


def encode_lsr(lsr: float) -> float:
    """Equation 1, normalized L-Log value. Does not clamp below 0 or above 1."""
    x = finite(lsr)
    return 8.0*x + 0.09 if x <= 0.006 else 0.27*math.log10(1.3*x+0.0115)+0.6


def decode_llog(value: float) -> float:
    """Equation 2, scene-linear reflection. Rounded branch constants retained."""
    y = finite(value)
    return (y-0.09)/8.0 if y <= 0.1380 else (10.0**((y-0.6)/0.27)-0.0115)/1.3


def matvec(matrix: Sequence[Sequence[float]], vector: Sequence[float]) -> tuple[float, float, float]:
    if len(vector) != 3:
        raise ValueError('Expected three components')
    v = tuple(finite(x) for x in vector)
    return tuple(sum(row[i]*v[i] for i in range(3)) for row in matrix)


def xyz_d65_to_llog(xyz: Sequence[float], exposure_ev: float = 0.0) -> tuple[float, float, float]:
    """Calibrated XYZ -> linear BT.2020 -> explicit EV gain -> L-Log.

    A D50-referenced DNG/ICC conversion is NOT a valid direct input: chromatic
    adaptation must happen upstream. This function never guesses source metadata.
    """
    gain = 2.0**finite(exposure_ev)
    rgb = matvec(XYZ_D65_TO_RGB2020, xyz)
    return tuple(encode_lsr(x*gain) for x in rgb)


def llog_to_xyz_d65(rgb: Sequence[float]) -> tuple[float, float, float]:
    if len(rgb) != 3:
        raise ValueError('Expected three components')
    return matvec(RGB2020_TO_XYZ_D65, tuple(decode_llog(x) for x in rgb))


if __name__ == '__main__':
    import json
    print(json.dumps({
        'implementation': 'LLOGREFERENCE1A',
        'source': 'Leica L-Log Reference Manual V1.9, equations 1/2',
        'samples': [{'lsr': x, 'llog_normalized': encode_lsr(x),
                     'normalized_times_1023': encode_lsr(x)*1023}
                    for x in (0.0, 0.02, 0.18, 0.90, 4.07, 8.15)],
        'not_implemented': ['phone source calibration', 'Pure/Cine LUT',
            'video codec level interpretation', 'SL3-P still-photo rendering'],
    }, indent=2))
