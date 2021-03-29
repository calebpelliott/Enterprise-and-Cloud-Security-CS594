package edu.stevens.cs594.crypto;

public class PlainText {
	
	public final byte[] contents;
	
	public final int length;
	
	public PlainText(byte[] c, int l) {
		this.contents = c;
		this.length = l;
	}
	
	public byte[] compactBytes() {
		if (contents.length == length) {
			return contents;
		} else {
			byte[] extract = new byte[length];
			for (int i = 0; i < length; i++) {
				extract[i] = contents[i];
			}
			return extract;
		}
	}


}
