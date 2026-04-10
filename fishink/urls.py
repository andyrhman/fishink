from django.urls import path

from .views import CertificateHistoryAPIView, PhishingCheckAPIView, WebsiteInsightAPIView, WebsiteScreenshotAPIView

urlpatterns = [
    path('phishing-check/', PhishingCheckAPIView.as_view(), name="phishing-check"),
    path('insight/', WebsiteInsightAPIView.as_view(), name="website-insight"),   
    path("certificate-history/", CertificateHistoryAPIView.as_view(), name="certificate-history"),
    path("screenshot/", WebsiteScreenshotAPIView.as_view(), name="website-screenshot"),   
]