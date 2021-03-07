package edu.stevens.cs594.chat.webapp.admin;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import javax.enterprise.context.SessionScoped;
import javax.faces.flow.FlowScoped;
import javax.inject.Inject;
import javax.inject.Named;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

import edu.stevens.cs594.chat.service.dto.RoleDto;
import edu.stevens.cs594.chat.service.dto.UserDto;
import edu.stevens.cs594.chat.service.dto.util.UserDtoFactory;
import edu.stevens.cs594.chat.service.ejb.IMessageService.MessageServiceExn;
import edu.stevens.cs594.chat.service.ejb.IMessageServiceLocal;
import edu.stevens.cs594.chat.service.messages.Messages;
import edu.stevens.cs594.chat.webapp.BaseBacking;
import edu.stevens.cs594.chat.webapp.Navigation;

/*
 * Apparently @FlowScoped requires JSF beans, won't work with CDI
 */
@Named("addUserBacking")
// @FlowScoped("addUser")
@SessionScoped
public class AddUser extends BaseBacking {

	private static final long serialVersionUID = 3044587376162867790L;
	
	private static final int QR_SIZE = 256;
	
	private static final String IMAGE_TYPE = "png";
	
	@SuppressWarnings("unused")
	private static Logger logger = Logger.getLogger(AddUser.class.getCanonicalName());

	/*
	 * Fill in these fields in a form to add a new user to the database.
	 */
	private String username;
	
	private String password;
	
	private String passwordAgain;
	
	/*
	 * Need to base64 encode OTP
	 */
	private Base64.Encoder encoder = Base64.getEncoder();
	
	/*
	 * Generated as part of user registration, including a random secret.
	 */
	private String keyUri;
	
	// Roles from the database
	private List<RoleDto> roles;
	
	// Selected roles
	private String[] selectedRoles;
	
	private String name;

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

    public String getPasswordAgain() {
        return passwordAgain;
    }
    public void setPasswordAgain(String passwordAgain) {
        this.passwordAgain = passwordAgain;
    }

    public String getKeyUri() {
    	return keyUri;
    }
    
    public void setKeyUri(String keyUri) {
        this.keyUri = keyUri;
    }
    
 	public List<RoleDto> getRoles() {
		return roles;
	}

	public String[] getSelectedRoles() {
		return selectedRoles;
	}

	public void setSelectedRoles(String[] selectedRoles) {
		this.selectedRoles = selectedRoles;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@Inject
	private IMessageServiceLocal userService;
	
	private UserDtoFactory userDtoFactory = new UserDtoFactory();
	
	/**
	 * Initialization: load available roles from the database.
	 */
	@PostConstruct
	public void init() {
		roles = userService.getRoles();
	}
	
	/**
	 * This performs the logic for adding the user to the database.
	 */
	public String addUser() {
		
		if (!password.equals(passwordAgain)) {
			addMessage(Messages.admin_user_nomatch_password);
			return null;
		}
		
		try {
			UserDto user = userDtoFactory.createUserDto();
			
			user.setUsername(username);
			
			user.setPassword(password);
			
			for (String role : selectedRoles) {
				user.getRoles().add(role);
			}
			user.setName(name);
			
			keyUri = userService.addUser(user);
			
			/*
			 * Redirect to the page that will display the generated QR code.
			 * Flowscope is used to share this backing bean with addUser and qrcode.
			 */
			return Navigation.NAV_ADMIN_ADDING_USER;

		} catch (MessageServiceExn e) {
			addMessage(e.getMessageCode());
			return null;
		}
	}
	
	private static byte[] createImage(String qrText)
			throws WriterException, IOException {

		// Create the BitMatrix for the QR-Code that encodes the given String
		Map<EncodeHintType, ErrorCorrectionLevel> hintMap = new HashMap<EncodeHintType, ErrorCorrectionLevel>();
		hintMap.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.L);
		QRCodeWriter qrCodeWriter = new QRCodeWriter();
		BitMatrix bitMatrix = qrCodeWriter.encode(qrText, BarcodeFormat.QR_CODE, QR_SIZE, QR_SIZE, hintMap);

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		MatrixToImageWriter.writeToStream(bitMatrix, IMAGE_TYPE, out);  		
		return out.toByteArray();
	}
	
	public String imageType() {
		return IMAGE_TYPE;
	}
	
	/*
	 * The image for the QR code will be embedded in the img link URI.
	 */
	public String qrCode() {
		try {
			return new String(encoder.encode(createImage(keyUri)), CHARSET);
		} catch (WriterException | IOException e) {
			throw new IllegalStateException("Failed to base64 encode QR code", e);
		}
		
	}
	
 }
