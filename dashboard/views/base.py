from django.shortcuts import render
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.http import JsonResponse, Http404
from django.utils.html import escape
from django.db.models import Sum, Count
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
import logging
import json
from datetime import datetime, timedelta, timezone

from dashboard.auth.decorators import require_permission, viewer_or_higher

# Set up logging
logger = logging.getLogger(__name__)

@viewer_or_higher
def uitest_view(request):
    """View for UI testing with DaisyUI components"""
    return render(request, 'dashboard/uitest.html')

def header_test_view(request):
    """View for testing header functionality without authentication"""
    return render(request, 'dashboard/header_test.html')