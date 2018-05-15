Token for {{ subject }}

{% if issuer == subject %}
Token has been issued for {{ subject }} for retrieving profile from link below.
{% else %}
{{ issuer }} has provided {{ subject }} a token for retrieving
profile from the link below.
{% endif %}

Click <a href="{{ url }}" target="_blank">here</a> to claim the token.
Token is usable until {{  token_expires }}{% if token_timezone %} ({{ token_timezone }} time){% endif %}.

