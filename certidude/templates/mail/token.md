Token for {{ user.name }}

{% if issuer == user %}
Token has been issued for {{ user }} for retrieving profile from link below.
{% else %}
{{ issuer }} has provided {{ user }} a token for retrieving
profile from the link below.
{% endif %}

Click [here]({{ url }}) to claim the token.
Token is usable until {{  token_expires }}{% if token_timezone %} ({{ token_timezone }} time){% endif %}.

