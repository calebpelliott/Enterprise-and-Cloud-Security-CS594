package edu.stevens.cs594.chat.webapp;

public class Navigation {
	
	/*
	 * Navigation bar.
	 */
	public static final String NAV_LOGIN = "NAV_LOGIN";
	public static final String NAV_ADMIN = "NAV_ADMIN";
	public static final String NAV_MODERATOR = "NAV_MODERATOR";
	public static final String NAV_POSTER = "NAV_POSTER";
	/*
	 * Login controller.
	 */
	public static final String NAV_LOGIN_ERROR = "NAV_LOGIN_ERROR";
	public static final String NAV_ADMIN_LOGGED_IN = "NAV_ADMIN_LOGGED_IN";
	public static final String NAV_MODERATOR_LOGGED_IN = "NAV_MODERATOR_LOGGED_IN";
	public static final String NAV_POSTER_LOGGED_IN = "NAV_POSTER_LOGGED_IN";
	public static final String NAV_LOGOUT_SUCCESS = "NAV_LOGOUT_SUCCESS";
	public static final String NAV_LOGOUT_FAILURE = "NAV_LOGOUT_FAILURE";
	/*
	 * Admin controllers.
	 */
	public static final String NAV_ADMIN_ADD_USER = "NAV_ADMIN_ADD_USER";
	public static final String NAV_ADMIN_EDIT_USER = "NAV_ADMIN_EDIT_USER";
	public static final String NAV_ADMIN_VIEW_USERS = "NAV_ADMIN_VIEW_USERS";
	public static final String NAV_ADMIN_ADDING_USER = "NAV_ADMIN_ADDING_USER";
	public static final String NAV_ADMIN_ADDED_USER = "NAV_ADMIN_ADDED_USER";
	public static final String NAV_ADMIN_EDITED_USER = "NAV_ADMIN_EDITED_USER";
	public static final String NAV_ADMIN_DUPLICATE_USER = "NAV_ADMIN_DUPLICATE_USER";
	
	/*
	 * Variables used to pass values through the request context.
	 */
	public static final String ADMIN_USER = "ADMIN_USER";
	
	/*
	 * Context root for mapping servlet that displays QR code
	 */
	public static final String QR_CODE_CONTEXT = "/qrcode/";
}
