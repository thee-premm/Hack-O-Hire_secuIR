"""
Personalized Bands Enrichment
Converts raw risk scores into categorical bands for rule evaluation.
Uses Redis baselines for user-specific thresholds when available.
"""

from typing import Dict, Optional


# ---- Threshold constants ----

RISK_THRESHOLDS = {'CRITICAL': 0.9, 'HIGH': 0.7, 'MEDIUM': 0.5, 'LOW': 0.3}

HIGH_RISK_COUNTRIES = {'NG', 'RU', 'CN', 'KP', 'IR', 'VE', 'BY', 'SY', 'MM', 'LY'}


class BandEnricher:
    """
    Enriches an incident dict with categorical bands derived from
    numeric scores and user baselines.  Downstream rules evaluate
    bands instead of raw numbers.
    """

    def __init__(self, baseline_manager=None):
        self.baseline_manager = baseline_manager

    # ------------------------------------------------------------------
    # PUBLIC
    # ------------------------------------------------------------------

    def enrich(self, incident: Dict, user_baseline: Optional[Dict] = None) -> Dict:
        """Return a *copy* of incident with band fields added."""
        e = incident.copy()

        risk = e.get('final_risk', 0)
        e['risk_band'] = self._risk_band(risk)

        # Amount band
        amount = e.get('amount', 0)
        if user_baseline and user_baseline.get('avg_transaction_amount'):
            avg = user_baseline['avg_transaction_amount']
            std = user_baseline.get('std_transaction_amount', max(avg * 0.5, 1))
            z = (amount - avg) / max(std, 1) if amount else 0
            e['amount_band'] = self._amount_band_z(z)
        else:
            e['amount_band'] = self._amount_band_abs(amount)

        # Device band
        dm = e.get('device_match_score', 1)
        e['device_band'] = 'NEW' if dm == 0 else ('KNOWN' if dm == 1 else 'UNKNOWN')

        # Location band
        lm = e.get('location_match_score', e.get('location_deviation_km', 0))
        if isinstance(lm, (int, float)) and lm > 500:
            e['location_band'] = 'NEW_COUNTRY'
        elif lm == 0:
            e['location_band'] = 'NEW_COUNTRY'
        else:
            e['location_band'] = 'KNOWN'

        # Login hour band
        core = e.get('core_features', {})
        hour = core.get('hour_of_day', 12)
        if user_baseline and user_baseline.get('avg_login_hour') is not None:
            avg_h = user_baseline['avg_login_hour']
            std_h = user_baseline.get('std_login_hour', 4)
            dev = abs(hour - avg_h) / max(std_h, 1)
            e['login_hour_band'] = ('VERY_UNUSUAL' if dev > 2
                                    else 'UNUSUAL' if dev > 1
                                    else 'TYPICAL')
        else:
            e['login_hour_band'] = 'UNUSUAL' if (hour < 6 or hour > 22) else 'TYPICAL'

        # Request rate band
        rate = core.get('session_avg_rate', 0)
        e['request_rate_band'] = ('BOT_LIKE' if rate > 100
                                  else 'HIGH' if rate > 50
                                  else 'ELEVATED' if rate > 20
                                  else 'NORMAL')

        # API diversity band
        entropy = core.get('session_entropy', 0)
        e['api_diversity_band'] = ('SCRAPING' if entropy > 2.5
                                   else 'UNUSUAL' if entropy > 1.5
                                   else 'NORMAL')

        # Country risk band
        cr = e.get('country_risk', 0)
        loc = e.get('raw_event', {}).get('location_country', '')
        if loc in HIGH_RISK_COUNTRIES or cr > 0.8:
            e['country_risk_band'] = 'CRITICAL'
        elif cr > 0.5:
            e['country_risk_band'] = 'HIGH'
        else:
            e['country_risk_band'] = 'LOW'

        # Convenience: bundle behavioral bands
        e['behavioral_context'] = {
            'login_hour_band': e.get('login_hour_band', 'TYPICAL'),
            'location_band': e.get('location_band', 'KNOWN'),
            'device_band': e.get('device_band', 'KNOWN'),
            'request_rate_band': e.get('request_rate_band', 'NORMAL'),
            'api_diversity_band': e.get('api_diversity_band', 'NORMAL'),
        }

        return e

    # ------------------------------------------------------------------
    # INTERNAL
    # ------------------------------------------------------------------

    @staticmethod
    def _risk_band(risk: float) -> str:
        if risk >= 0.9:
            return 'CRITICAL'
        if risk >= 0.7:
            return 'HIGH'
        if risk >= 0.5:
            return 'MEDIUM'
        if risk >= 0.3:
            return 'LOW'
        return 'VERY_LOW'

    @staticmethod
    def _amount_band_z(z: float) -> str:
        az = abs(z)
        if az >= 5:
            return 'EXTREME'
        if az >= 2:
            return 'HIGH'
        return 'TYPICAL'

    @staticmethod
    def _amount_band_abs(amount: float) -> str:
        if amount > 50000:
            return 'EXTREME'
        if amount > 10000:
            return 'HIGH'
        if amount > 1000:
            return 'MEDIUM'
        return 'TYPICAL'
