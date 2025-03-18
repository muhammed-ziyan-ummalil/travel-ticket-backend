from django.contrib import admin
from django.urls import path
from rest_framework.authtoken.views import obtain_auth_token
from . import views
from .views import create_admin


urlpatterns = [

    # =================== AUTHENTICATION ===================
    path('register_admin/', create_admin, name='create-admin'),
    path('admin_login/', views.admin_login, name='admin-login'),
    path('userlogin/', views.user_login, name='user-login'),
    path('logout/', views.user_logout, name='user-logout'),

    # =================== USER MANAGEMENT ===================
    path('add_user/', views.add_user, name='add-user'),
    path('delete_user/<str:email>/', views.delete_user, name='delete-user'),
    path('admin/update-user/<int:user_id>/', views.update_user, name='update-user'),

    # =================== EMPLOYEE APIs ===================
    path('employee/dashboard/', views.employee_view_dashboard, name='employee-dashboard'),
    path('employee/view-request/<int:request_id>/', views.employee_view_request, name='employee-view-request'),
    path('employee/edit-request/<int:request_id>/', views.employee_edit_request, name='employee-edit-request'),
    path('employee/cancel-request/<int:request_id>/', views.employee_cancel_request, name='employee-cancel-request'),
    path('employee/submit-request/', views.employee_submit_request, name='employee-submit-request'),
    path('employee/resubmit-request/<int:request_id>/', views.employee_resubmit_request, name='employee-resubmit-request'),

    # =================== MANAGER APIs ===================

path('manager/view-requests/', views.manager_view_requests, name='manager-view-requests'),
path('manager_handle_request/', views.manager_handle_request, name='manager-approve-request'), 


    # =================== ADMIN APIs ===================
    path('admin/view-request/<int:request_id>/', views.get_travel_requests, name='view_request'),
    path('admin/view-request/<int:request_id>/', views.get_travel_requests, name='view_request'),
    path('admin/update-request/<int:request_id>/', views.update_travel_request_status, name='admin-update-request'),
    path('admin/request-info/<int:request_id>/', views.request_additional_info, name='admin-request-info'),
    path('admin/process-close-request/<int:request_id>/', views.process_and_close_travel_request, name='admin-process-close-request'),
    path('admin/view-request/close/<int:request_id>/', views.close_approved_requests, name='close_approved_request'),
    # =================== DATA LIST APIs ===================
    path('api/employees/', views.get_all_employees, name='all-employees'),
    path('admin/managers/', views.get_all_managers, name='all-managers'),

]