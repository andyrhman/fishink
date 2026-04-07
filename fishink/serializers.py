from rest_framework import serializers

class URLCheckSerializer(serializers.Serializer):
    url = serializers.JSONField()

    def validate_url(self, value):
        if isinstance(value, str):
            value = {"value": value}

        if not isinstance(value, dict):
            raise serializers.ValidationError("url must be a string or an object.")

        raw = value.get("value") or value.get("raw") or value.get("url")
        if not raw or not isinstance(raw, str):
            raise serializers.ValidationError("url.value is required and must be a string.")

        return {"value": raw.strip()}
    
class WebsiteInsightSerializer(serializers.Serializer):
    url = serializers.CharField()

    def validate_url(self, value):
        value = str(value).strip()
        if not value:
            raise serializers.ValidationError("url is required.")
        return value   
    
class CertificateHistorySerializer(serializers.Serializer):
    url = serializers.CharField()

    def validate_url(self, value):
        value = str(value).strip()
        if not value:
            raise serializers.ValidationError("url is required.")
        return value
    
class ScreenshotSerializer(serializers.Serializer):
    url = serializers.CharField()

    def validate_url(self, value):
        value = str(value).strip()
        if not value:
            raise serializers.ValidationError("url is required.")
        return value   