from django.http import HttpResponse  # Import HttpResponse for returning HTTP responses
from django.shortcuts import redirect  # Import redirect for redirecting to other views
from rest_framework.decorators import api_view, authentication_classes, permission_classes  # Import decorators for API views, authentication, and permissions
from rest_framework.permissions import IsAuthenticated  # Import IsAuthenticated permission class
from rest_framework.authentication import TokenAuthentication  # Import TokenAuthentication for token-based authentication
from rest_framework.response import Response  # Import Response for returning API responses
from rest_framework import status  # Import status for HTTP status codes
from rest_framework.status import (
    HTTP_200_OK,
    HTTP_201_CREATED,
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_500_INTERNAL_SERVER_ERROR,
)  # Import specific HTTP status codes
from django.contrib.auth.models import User  # Import User model for user authentication
from django.contrib.auth import authenticate  # Import authenticate for user authentication
from django.contrib.auth.hashers import make_password  # Import make_password for hashing passwords
from rest_framework.authtoken.models import Token  # Import Token model for token-based authentication
from django.core.mail import send_mail  # Import send_mail for sending emails
from datetime import date  # Import date for date operations
from .models import TravelApplication  # Import TravelApplication model
from rest_framework.decorators import api_view, permission_classes  # Import decorators for API views and permissions
from rest_framework.permissions import IsAuthenticated  # Import IsAuthenticated permission class
from rest_framework.response import Response  # Import Response for returning API responses
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND, HTTP_200_OK  # Import specific HTTP status codes
from .models import TravelApplication  # Import TravelApplication model
from .models import TravelApplication, EmployeeProfile, ManagerProfile, Profile, AdminUser  # Import models for travel application, employee, manager, profile, and admin user
from .serializers import (AdminCreateSerializer, ProfileInfoSerializer, AdminDetailSerializer,
                        ManagerDetailSerializer, EmployeeDetailSerializer, 
                        EmployeeTravelRequestViewSerializer, ManagerTravelApprovalSerializer,
                        AdminTravelOverviewSerializer, TravelApplicationSerializer)  # Import serializers for various models
from .serializers import TravelRequestSerializer  # Import TravelRequestSerializer
from django.db.models import Q

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def employee_view_dashboard(request):
    """
    Retrieve all travel requests submitted by the authenticated employee.
    """
    try:
        employee = EmployeeProfile.objects.get(profile__user=request.user)  # Get the employee profile of the authenticated user
        travel_requests = TravelApplication.objects.filter(employee=employee)  # Get all travel requests submitted by the employee
        serializer = EmployeeTravelRequestViewSerializer(travel_requests, many=True)  # Serialize the travel requests
        return Response(serializer.data, status=status.HTTP_200_OK)  # Return the serialized data with HTTP 200 OK status
    except EmployeeProfile.DoesNotExist:
        return Response({"error": "Employee profile not found."}, status=status.HTTP_404_NOT_FOUND)  # Return error if employee profile is not found

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def employee_view_request(request, request_id):
    """
    Retrieve a specific travel request by ID, ensuring it belongs to the authenticated employee.
    """
    try:
        employee = EmployeeProfile.objects.get(profile__user=request.user)  # Get the employee profile of the authenticated user
        travel_request = TravelApplication.objects.get(id=request_id, employee=employee)  # Get the travel request by ID and ensure it belongs to the employee
        serializer = EmployeeTravelRequestViewSerializer(travel_request)  # Serialize the travel request
        return Response(serializer.data, status=status.HTTP_200_OK)  # Return the serialized data with HTTP 200 OK status
    except EmployeeProfile.DoesNotExist:
        return Response({"error": "Employee profile not found."}, status=status.HTTP_404_NOT_FOUND)  # Return error if employee profile is not found
    except TravelApplication.DoesNotExist:
        return Response({"error": "Travel request not found or unauthorized access."}, status=status.HTTP_404_NOT_FOUND)  # Return error if travel request is not found or unauthorized access

@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def employee_edit_request(request, request_id):
    """
    Allows an employee to edit their travel request by ID.
    """
    try:
        travel_request = TravelApplication.objects.get(id=request_id)  # Get the travel request by ID
    except TravelApplication.DoesNotExist:
        return Response({"error": "Travel request not found."}, status=HTTP_404_NOT_FOUND)  # Return error if travel request is not found

    serializer = EmployeeTravelRequestViewSerializer(travel_request, data=request.data, partial=True)  # Serialize the travel request with partial update
    if serializer.is_valid():
        serializer.save()  # Save the updated travel request
        return Response(
            {
                "message": "Travel request updated successfully.",
                "data": serializer.data,
            },
            status=HTTP_200_OK
        )  # Return success message with serialized data and HTTP 200 OK status
    return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)  # Return validation errors with HTTP 400 BAD REQUEST status

@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def employee_cancel_request(request, request_id):
    """
    Allows an employee to cancel a travel request if:
    - It is not approved or rejected.
    """
    try:
        travel_request = TravelApplication.objects.get(id=request_id)  # Get the travel request by ID
    except TravelApplication.DoesNotExist:
        return Response({"error": "Travel request not found."}, status=HTTP_404_NOT_FOUND)  # Return error if travel request is not found

    if travel_request.status in ["approved", "rejected"]:
        return Response({"error": "Approved or rejected requests cannot be cancelled."}, status=HTTP_400_BAD_REQUEST)  # Return error if travel request is approved or rejected

    travel_request.status = "cancelled"  # Update the status to cancelled
    travel_request.is_closed = True  # Mark the travel request as closed
    travel_request.save()  # Save the updated travel request

    return Response({"message": "Travel request cancelled successfully."}, status=HTTP_200_OK)  # Return success message with HTTP 200 OK status


@api_view(["POST"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def employee_submit_request(request):
    """
    Allows an employee to submit a new travel request.
    """
    try:
        employee = EmployeeProfile.objects.get(profile__user=request.user)  # Get the employee profile of the authenticated user
    except EmployeeProfile.DoesNotExist:
        return Response({"error": "Employee profile not found."}, status=HTTP_404_NOT_FOUND)  # Return error if employee profile is not found

    data = request.data
    start_date_str = data.get("start_date")
    end_date_str = data.get("end_date")

    if not start_date_str or not end_date_str:
        return Response({"error": "Start date and end date are required."}, status=HTTP_400_BAD_REQUEST)  # Return error if start date or end date is missing

    try:
        start_date = date.fromisoformat(start_date_str)
        end_date = date.fromisoformat(end_date_str)
    except ValueError:
        return Response({"error": "Invalid date format. Use YYYY-MM-DD."}, status=HTTP_400_BAD_REQUEST)  # Return error if date format is invalid

    if start_date < date.today():
        return Response({"error": "Start date must be in the future."}, status=HTTP_400_BAD_REQUEST)  # Return error if start date is in the past

    if end_date <= start_date:
        return Response({"error": "End date must be after start date."}, status=HTTP_400_BAD_REQUEST)  # Return error if end date is before or same as start date

    serializer = EmployeeTravelRequestViewSerializer(data=data)
    if serializer.is_valid():
        travel_request = serializer.save(employee=employee, manager=employee.manager)  # Save the travel request with employee and manager info
        return Response(
            {
                "message": "Travel request submitted successfully.",
                "data": EmployeeTravelRequestViewSerializer(travel_request).data,
            },
            status=HTTP_201_CREATED
        )  # Return success message with serialized data and HTTP 201 CREATED status
    return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)  # Return validation errors with HTTP 400 BAD REQUEST status


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def employee_resubmit_request(request, request_id):
    """
    Allows an employee to resubmit a travel request if marked as 'requested_for_info'.
    """
    try:
        travel_request = TravelApplication.objects.get(id=request_id)  # Get the travel request by ID
    except TravelApplication.DoesNotExist:
        return Response({"error": "Travel request not found."}, status=HTTP_404_NOT_FOUND)  # Return error if travel request is not found

    if travel_request.status != "pending":
        return Response({"error": "Only requests requiring more info can be resubmitted."}, status=HTTP_400_BAD_REQUEST)  # Return error if request is not pending

    if not request.data:
        return Response({"error": "At least one field must be updated before resubmission."}, status=HTTP_400_BAD_REQUEST)  # Return error if no data is provided

    serializer = EmployeeTravelRequestViewSerializer(travel_request, data=request.data, partial=True)
    if serializer.is_valid():
        travel_request.status = "pending"  # Update the status to pending
        serializer.save()  # Save the updated travel request
        return Response(
            {
                "message": "Travel request resubmitted successfully.",
                "data": serializer.data,
            },
            status=HTTP_200_OK
        )  # Return success message with serialized data and HTTP 200 OK status
    return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)  # Return validation errors with HTTP 400 BAD REQUEST status

@api_view(['GET'])
def manager_view_requests(request):
    """
    Manager: View travel requests with optional filters.
    """
    try:
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')
        employee_name = request.GET.get('employee_name')
        status_filter = request.GET.get('status')

        requests = TravelApplication.objects.select_related('employee').all()  # Get all travel requests with related employee info

        if start_date and end_date:
            requests = requests.filter(start_date__gte=start_date, end_date__lte=end_date)  # Filter requests by date range
        if employee_name:
            requests = requests.filter(employee__first_name__icontains=employee_name)  # Filter requests by employee name
        if status_filter:
            requests = requests.filter(status=status_filter)  # Filter requests by status

        serializer = EmployeeTravelRequestViewSerializer(requests, many=True)
        return Response(serializer.data, status=HTTP_200_OK)  # Return serialized data with HTTP 200 OK status

    except Exception as e:
        return Response(
            {"error": f"Failed to retrieve requests: {str(e)}"},
            status=HTTP_500_INTERNAL_SERVER_ERROR
        )  # Return error if an exception occurs

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def manager_handle_request(request):
    """
    Manager: Approve or Reject a travel request.
    """
    request_id = request.data.get('request_id')
    status = request.data.get('status')
    reason = request.data.get('reason', '')

    if not request_id or status not in ["approved", "rejected"]:
        return Response({"error": "Invalid request data"}, status=HTTP_400_BAD_REQUEST)  # Return error if request data is invalid

    try:
        travel_request = TravelApplication.objects.get(id=request_id)  # Get the travel request by ID

        if travel_request.status != "pending":
            return Response({"error": "Only pending requests can be modified."}, status=HTTP_400_BAD_REQUEST)  # Return error if request is not pending

        travel_request.status = status  # Update the status

        if status == "rejected":
            if not reason:
                return Response({"error": "Rejection reason is required."}, status=HTTP_400_BAD_REQUEST)  # Return error if rejection reason is missing
            travel_request.rejection_reason = reason  # Update the rejection reason
            travel_request.is_closed = True  # Mark the travel request as closed

        travel_request.save()  # Save the updated travel request

        return Response({"message": f"Request {status} successfully"}, status=HTTP_200_OK)  # Return success message with HTTP 200 OK status

    except TravelApplication.DoesNotExist:
        return Response({"error": "Travel request not found."}, status=HTTP_404_NOT_FOUND)  # Return error if travel request is not found



@api_view(['GET'])
def get_travel_requests(request, request_id=None):
    """
    Admin: View all travel requests with filters and sorting or get details of a specific request.
    """
    try:
        if request_id:
            travel_request = TravelApplication.objects.select_related('employee').get(id=request_id)  # Get the travel request by ID with related employee info
            serializer = EmployeeTravelRequestViewSerializer(travel_request)
            return Response(serializer.data, status=HTTP_200_OK)  # Return serialized data with HTTP 200 OK status
        else:
            start_date = request.GET.get('start_date')
            end_date = request.GET.get('end_date')
            employee_name = request.GET.get('employee_name')
            status_filter = request.GET.get('status')
            order_by = request.GET.get('order_by', 'id')

            requests = TravelApplication.objects.select_related('employee').all()  # Get all travel requests with related employee info

            if start_date and end_date:
                requests = requests.filter(start_date__gte=start_date, end_date__lte=end_date)  # Filter requests by date range
            if employee_name:
                requests = requests.filter(employee__first_name__icontains=employee_name)  # Filter requests by employee name
            if status_filter:
                requests = requests.filter(status=status_filter)  # Filter requests by status

            requests = requests.order_by(order_by)  # Order requests by specified field
            serializer = EmployeeTravelRequestViewSerializer(requests, many=True)
            return Response(serializer.data, status=HTTP_200_OK)  # Return serialized data with HTTP 200 OK status

    except TravelApplication.DoesNotExist:
        return Response({"error": "Travel request not found."}, status=HTTP_404_NOT_FOUND)  # Return error if travel request is not found
    except Exception as e:
        return Response(
            {"error": f"Failed to retrieve travel requests: {str(e)}"},
            status=HTTP_500_INTERNAL_SERVER_ERROR
        )  # Return error if an exception occurs


@api_view(['PUT'])
def update_travel_request_status(request, request_id):
    """
    Update status of a specific travel request.
    """
    try:
        travel_request = TravelApplication.objects.get(id=request_id)  # Get the travel request by ID
        new_status = request.data.get("status")  # Get the new status from the request data

        if not new_status:
            return Response({"error": "Status is required."}, status=HTTP_400_BAD_REQUEST)  # Return error if status is not provided

        travel_request.status = new_status  # Update the status
        travel_request.save()  # Save the updated travel request

        return Response(
            {"message": "Status updated successfully.", "new_status": new_status},
            status=HTTP_200_OK
        )  # Return success message with new status and HTTP 200 OK status

    except TravelApplication.DoesNotExist:
        return Response({"error": "Travel request not found."}, status=HTTP_404_NOT_FOUND)  # Return error if travel request is not found

    except Exception as e:
        return Response({"error": f"Failed to update status: {str(e)}"}, status=HTTP_500_INTERNAL_SERVER_ERROR)  # Return error if an exception occurs


@api_view(['DELETE'])
def process_and_close_travel_request(request, request_id):
    """
    Delete an approved travel request (mark as closed).
    """
    try:
        travel_request = TravelApplication.objects.get(id=request_id)  # Get the travel request by ID

        if travel_request.status != "approved":
            return Response(
                {"error": "Only approved requests can be closed."},
                status=HTTP_400_BAD_REQUEST
            )  # Return error if request is not approved

        travel_request.delete()  # Delete the travel request
        return Response({"message": "Approved travel request closed successfully."}, status=HTTP_200_OK)  # Return success message with HTTP 200 OK status

    except TravelApplication.DoesNotExist:
        return Response({"error": "Travel request not found."}, status=HTTP_404_NOT_FOUND)  # Return error if travel request is not found

    except Exception as e:
        return Response({"error": f"Error occurred: {str(e)}"}, status=HTTP_500_INTERNAL_SERVER_ERROR)  # Return error if an exception occurs


@api_view(['GET'])
def get_all_employees(request):
    """
    Get list of all employees.
    """
    employees = EmployeeProfile.objects.all()  # Get all employee profiles
    serializer = EmployeeDetailSerializer(employees, many=True)  # Serialize the employee profiles
    return Response(serializer.data, status=HTTP_200_OK)  # Return serialized data with HTTP 200 OK status


@api_view(['GET'])
def get_all_managers(request):
    """
    Get list of all managers.
    """
    managers = ManagerProfile.objects.all()  # Get all manager profiles
    serializer = ManagerDetailSerializer(managers, many=True)  # Serialize the manager profiles
    return Response(serializer.data, status=HTTP_200_OK)  # Return serialized data with HTTP 200 OK status


@api_view(['PUT'])
def update_user(request, user_id):
    """
    Update an employee or manager's profile.
    """
    try:
        # First try to find an employee
        try:
            user = EmployeeProfile.objects.get(id=user_id)  # Get the employee profile by ID
            serializer = EmployeeDetailSerializer(user, data=request.data, partial=True)  # Serialize the employee profile with partial update
        except EmployeeProfile.DoesNotExist:
            # If not found, try to find a manager
            user = ManagerProfile.objects.get(id=user_id)  # Get the manager profile by ID
            serializer = ManagerDetailSerializer(user, data=request.data, partial=True)  # Serialize the manager profile with partial update
            
        if serializer.is_valid():
            serializer.save()  # Save the updated profile
            return Response(serializer.data, status=HTTP_200_OK)  # Return serialized data with HTTP 200 OK status
        return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)  # Return validation errors with HTTP 400 BAD REQUEST status

    except (EmployeeProfile.DoesNotExist, ManagerProfile.DoesNotExist):
        return Response({"error": "User not found."}, status=HTTP_404_NOT_FOUND)  # Return error if user profile is not found


@api_view(['POST'])
def request_additional_info(request, request_id):
    """
    Admin: Request additional info for a travel request via email.
    """
    try:
        travel_request = TravelApplication.objects.select_related('employee').get(id=request_id)  # Get the travel request by ID with related employee info

        travel_request.status = "update"  # Update the status to update
        travel_request.save()  # Save the updated travel request

        send_mail(
            subject="Additional Information Required",
            message=f"Dear {travel_request.employee.first_name},\n\n"
                    "Please provide additional details for your travel request.",
            from_email="admin@company.com",
            recipient_list=[travel_request.employee.email],
        )  # Send email requesting additional information

        return Response(
            {"message": "Request for additional information sent successfully."},
            status=HTTP_200_OK
        )  # Return success message with HTTP 200 OK status

    except TravelApplication.DoesNotExist:
        return Response({"error": "Travel request not found."}, status=HTTP_404_NOT_FOUND)  # Return error if travel request is not found

    except Exception as e:
        return Response({"error": f"Failed to request additional info: {str(e)}"}, status=HTTP_500_INTERNAL_SERVER_ERROR)  # Return error if an exception occurs
    
@api_view(['POST'])
def create_admin(request):
    """
    Create a new admin user (multiple allowed).
    """
    serializer = AdminCreateSerializer(data=request.data)  # Serialize the admin creation data
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)  # Return validation errors with HTTP 400 BAD REQUEST status

    validated_data = serializer.validated_data
    username = validated_data.get("username")
    password = validated_data.get("password")
    email = validated_data.get("email")

    if User.objects.filter(email=email).exists():
        return Response({"error": "Email already exists."}, status=status.HTTP_400_BAD_REQUEST)  # Return error if email already exists

    try:
        user = User.objects.create_user(username=username, password=password, email=email)  # Create a new user

        admin = AdminUser.objects.create(
            user=user,
            username=username,
            password=make_password(password),
            email=email
        )  # Create a new admin user

        return Response({
            "message": "Admin created successfully.",
            "admin": AdminDetailSerializer(admin).data
        }, status=status.HTTP_201_CREATED)  # Return success message with serialized admin data and HTTP 201 CREATED status

    except Exception as e:
        return Response({"error": f"An error occurred while creating admin: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)  # Return error if an exception occurs


@api_view(['POST'])
def admin_login(request):
    """
    Admin login view with token authentication.
    """
    username = request.data.get('username')
    password = request.data.get('password')

    if not username or not password:
        return Response({"error": "Username and password are required."}, status=status.HTTP_400_BAD_REQUEST)  # Return error if username or password is missing

    user = authenticate(username=username, password=password)  # Authenticate the user

    if user and hasattr(user, 'admin_info'):
        token, _ = Token.objects.get_or_create(user=user)  # Get or create a token for the user
        return Response({"message": "Login successful", "token": token.key}, status=status.HTTP_200_OK)  # Return success message with token and HTTP 200 OK status

    return Response({"error": "Invalid credentials or user is not an admin."}, status=status.HTTP_401_UNAUTHORIZED)  # Return error if credentials are invalid or user is not an admin


@api_view(['POST'])
def user_login(request):
    """
    Login view for manager and employee roles.
    """
    username = request.data.get('username')
    password = request.data.get('password')

    if not username or not password:
        return Response({"error": "Username and password are required."}, status=status.HTTP_400_BAD_REQUEST)  # Return error if username or password is missing

    user = authenticate(username=username, password=password)  # Authenticate the user
    if not user:
        return Response({"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)  # Return error if credentials are invalid

    profile = Profile.objects.filter(user=user).first()  # Get the user profile
    if not profile:
        return Response({"error": "User profile not found."}, status=status.HTTP_404_NOT_FOUND)  # Return error if user profile is not found

    if profile.role not in ["manager", "employee"]:
        return Response({"error": "Unauthorized user role."}, status=status.HTTP_403_FORBIDDEN)  # Return error if user role is unauthorized

    token, _ = Token.objects.get_or_create(user=user)  # Get or create a token for the user

    return Response({
        "message": "Login successful",
        "token": token.key,
        "role": profile.role,
        "status": profile.status
    }, status=status.HTTP_200_OK)  # Return success message with token, role, status, and HTTP 200 OK status


@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def user_logout(request):
    """
    Logout the current user by deleting their token.
    """
    try:
        request.user.auth_token.delete()  # Delete the user's token
        return Response({"message": "Logout successful."}, status=status.HTTP_200_OK)  # Return success message with HTTP 200 OK status
    except Exception:
        return Response({"error": "Something went wrong."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)  # Return error if an exception occurs


@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def add_user(request):
    """
    Add a new Manager or Employee (Only Admin can perform).
    """
    if not hasattr(request.user, 'admin_info'):
        return Response({"error": "Only admins can add users."}, status=status.HTTP_403_FORBIDDEN)  # Return error if user is not an admin

    user_type = request.data.get("user_type")
    if user_type not in ["manager", "employee"]:
        return Response({"error": "Invalid user_type. Choose 'manager' or 'employee'."}, status=status.HTTP_400_BAD_REQUEST)  # Return error if user_type is invalid

    username = request.data.get("username")
    email = request.data.get("email")
    password = request.data.get("password")

    if not all([username, email, password]):
        return Response({"error": "Username, email, and password are required."}, status=status.HTTP_400_BAD_REQUEST)  # Return error if username, email, or password is missing

    if User.objects.filter(username=username).exists():
        return Response({"error": "Username already exists."}, status=status.HTTP_400_BAD_REQUEST)  # Return error if username already exists

    if User.objects.filter(email=email).exists():
        return Response({"error": "Email already exists."}, status=status.HTTP_400_BAD_REQUEST)  # Return error if email already exists

    first_name = request.data.get("first_name")
    last_name = request.data.get("last_name")
    gender = request.data.get("gender", "Not Specified")
    designation = request.data.get("designation", "HR")
    status_choice = request.data.get("status", "active")

    if not all([first_name, last_name, designation]):
        return Response({"error": "First name, last name, and designation are required."}, status=status.HTTP_400_BAD_REQUEST)  # Return error if first name, last name, or designation is missing

    user = User.objects.create_user(username=username, email=email, password=password)  # Create a new user

    profile = Profile.objects.create(user=user, role=user_type, status=status_choice)  # Create a new profile

    if user_type == "manager":
        manager = ManagerProfile.objects.create(
            profile=profile,
            first_name=first_name,
            last_name=last_name,
            gender=gender,
            email=email,
            status=status_choice,
            designation=designation
        )  # Create a new manager profile
        return Response({"message": "Manager created successfully.", "manager": ManagerDetailSerializer(manager).data},
                        status=status.HTTP_201_CREATED)  # Return success message with serialized manager data and HTTP 201 CREATED status

    if user_type == "employee":
        manager_id = request.data.get("manager")
        manager = None
        if manager_id:
            try:
                manager = ManagerProfile.objects.get(id=manager_id)  # Get the manager profile by ID
            except ManagerProfile.DoesNotExist:
                return Response({"error": "Manager not found."}, status=status.HTTP_400_BAD_REQUEST)  # Return error if manager profile is not found

        employee = EmployeeProfile.objects.create(
            profile=profile,
            first_name=first_name,
            last_name=last_name,
            gender=gender,
            email=email,
            status=status_choice,
            designation=designation,
            manager=manager
        )  # Create a new employee profile
        return Response({"message": "Employee created successfully.", "employee": EmployeeDetailSerializer(employee).data},
                        status=status.HTTP_201_CREATED)  # Return success message with serialized employee data and HTTP 201 CREATED status


@api_view(['DELETE'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def delete_user(request, email):
    """
    Delete a user (Only Admin can delete Managers or Employees).
    """
    if not hasattr(request.user, 'admin_info'):
        return Response({"error": "Only admins can delete users."}, status=status.HTTP_403_FORBIDDEN)  # Return error if user is not an admin

    try:
        user = User.objects.get(email=email)  # Get the user by email
    except User.DoesNotExist:
        return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)  # Return error if user is not found

    if hasattr(user, 'extended_profile'):
        profile = user.extended_profile
        if hasattr(profile, 'employee_info'):
            profile.employee_info.delete()  # Delete the employee profile
            profile.delete()  # Delete the profile
            user.delete()  # Delete the user
            return Response({"message": "Employee deleted successfully."}, status=status.HTTP_200_OK)  # Return success message with HTTP 200 OK status
        elif hasattr(profile, 'manager_info'):
            if EmployeeProfile.objects.filter(manager=profile.manager_info).exists():
                return Response({"error": "Cannot delete manager with assigned employees."}, status=status.HTTP_400_BAD_REQUEST)  # Return error if manager has assigned employees
            profile.manager_info.delete()  # Delete the manager profile
            profile.delete()  # Delete the profile
            user.delete()  # Delete the user
            return Response({"message": "Manager deleted successfully."}, status=status.HTTP_200_OK)  # Return success message with HTTP 200 OK status

    return Response({"error": "User is neither an Employee nor a Manager."}, status=status.HTTP_400_BAD_REQUEST)  # Return error if user is neither an employee nor a manager

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_travel_requests(request):
    """
    Allows the admin to view all travel requests.
    """
    travel_requests = TravelApplication.objects.all()  # Fetch all travel requests
    if not travel_requests:
        return Response({"message": "No travel requests found."}, status=HTTP_404_NOT_FOUND)  # Return message if no travel requests are found

    # Serialize the travel requests
    serializer = AdminTravelOverviewSerializer(travel_requests, many=True)  # Serialize the travel requests

    return Response({
        "message": "Travel requests fetched successfully.",
        "data": serializer.data
    }, status=HTTP_200_OK)  # Return success message with serialized data and HTTP 200 OK status

@api_view(['GET'])
def get_travel_requests(request, request_id):
    """
    Get details of a specific travel request by ID.
    """
    try:
        travel_request = TravelApplication.objects.get(id=request_id)  # Get the travel request by ID
        serializer = TravelApplicationSerializer(travel_request)  # Serialize the travel request
        return Response(serializer.data)  # Return serialized data
    except TravelApplication.DoesNotExist:
        return Response({"error": "Travel request not found"}, status=404)  # Return error if travel request is not found

@api_view(['POST'])
def close_approved_requests(request, request_id):
    """
    Close an approved travel request.
    """
    user = request.user  # Get the current user

    try:
        travel_request = TravelApplication.objects.get(id=request_id, status='approved')  # Get the approved travel request by ID
        
        travel_request.status = 'closed'  # Update the status to closed
        travel_request.save()  # Save the updated travel request
        
        return redirect('admin:view-request', request_id=request_id)  # Redirect to the admin view request page
    
    except TravelApplication.DoesNotExist:
        return HttpResponse("Travel request not found or not approved.", status=404)  # Return error if travel request is not found or not approved


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def admin_request_info(request):
    """
    Admin sends an email to an employee requesting additional information.
    """
    admin_user = request.user  # Get the authenticated admin user

    employee_id = request.data.get("employee_id")  # Get employee ID from request
    subject = request.data.get("subject", "Additional Information Required")  # Get subject from request or use default
    message = request.data.get("message")  # Get message from request

    if not employee_id or not message:
        return Response({"error": "Employee ID and message are required."}, status=HTTP_400_BAD_REQUEST)  # Return error if employee ID or message is missing

    try:
        employee = EmployeeProfile.objects.get(id=employee_id)  # Get the employee profile by ID
        recipient_email = employee.profile.user.email  # Get the employee's email
    except EmployeeProfile.DoesNotExist:
        return Response({"error": "Employee not found."}, status=HTTP_404_NOT_FOUND)  # Return error if employee profile is not found

    try:
        send_mail(
            subject,
            message,
            "admin@example.com",  # Replace with your sender email
            [recipient_email],
            fail_silently=False,
        )  # Send email requesting additional information
        return Response({"message": "Email sent successfully."}, status=HTTP_200_OK)  # Return success message with HTTP 200 OK status
    except Exception as e:
        return Response({"error": f"Failed to send email: {str(e)}"}, status=HTTP_500_INTERNAL_SERVER_ERROR)  # Return error if an exception occurs


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def filter_travel_requests(request):
    """
    Allows the admin to filter and sort travel requests based on parameters.
    """
    travel_requests = TravelApplication.objects.all()  # Fetch all travel requests

    # Extract filter and sort parameters from query params
    status = request.query_params.get('status')
    employee_id = request.query_params.get('employee_id')
    start_date = request.query_params.get('start_date')
    end_date = request.query_params.get('end_date')
    sort_by = request.query_params.get('sort_by', 'created_at')
    sort_order = request.query_params.get('sort_order', 'desc')

    # Apply filters
    if status:
        travel_requests = travel_requests.filter(status=status)  # Filter by status
    if employee_id:
        travel_requests = travel_requests.filter(employee_id=employee_id)  # Filter by employee ID
    if start_date and end_date:
        travel_requests = travel_requests.filter(Q(start_date__gte=start_date) & Q(end_date__lte=end_date))  # Filter by date range

    # Apply sorting
    if sort_order == 'asc':
        travel_requests = travel_requests.order_by(sort_by)  # Sort in ascending order
    else:
        travel_requests = travel_requests.order_by(f"-{sort_by}")  # Sort in descending order

    if not travel_requests.exists():
        return Response({"message": "No matching travel requests found."}, status=HTTP_404_NOT_FOUND)  # Return message if no matching travel requests are found

    serializer = AdminTravelOverviewSerializer(travel_requests, many=True)  # Serialize the filtered travel requests
    return Response({
        "message": "Filtered travel requests fetched successfully.",
        "data": serializer.data
    }, status=HTTP_200_OK)  # Return success message with serialized data and HTTP 200 OK status
