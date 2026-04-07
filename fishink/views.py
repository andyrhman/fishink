from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .serializers import (
    ScreenshotSerializer,
    URLCheckSerializer,
    WebsiteInsightSerializer,
    CertificateHistorySerializer,
)
from .ml_service import predict_phishing
from .insight_service import build_website_insight
from .certificate_service import build_certificate_history
from .screenshot_service import capture_website_screenshot

class PhishingCheckAPIView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = URLCheckSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        raw_url = serializer.validated_data["url"]["value"]
        result = predict_phishing(raw_url)

        return Response(
            {
                "success": True,
                "data": result,
            },
            status=status.HTTP_200_OK,
        )
        
class WebsiteInsightAPIView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = WebsiteInsightSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        raw_url = serializer.validated_data["url"]
        result = build_website_insight(raw_url)

        return Response(
            {"success": True, "data": result},
            status=status.HTTP_200_OK,
        )       
        
class CertificateHistoryAPIView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = CertificateHistorySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        raw_url = serializer.validated_data["url"]
        result = build_certificate_history(raw_url)

        return Response({"success": True, "data": result}, status=status.HTTP_200_OK)
    
class WebsiteScreenshotAPIView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = ScreenshotSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        raw_url = serializer.validated_data["url"]
        result = capture_website_screenshot(raw_url)

        if not result.get("success"):
            return Response(result, status=status.HTTP_400_BAD_REQUEST)

        return Response({"success": True, "data": result}, status=status.HTTP_200_OK)