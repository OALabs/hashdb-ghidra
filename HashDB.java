//Script to look up API functions in HashDB (https://hashdb.openanalysis.net/)
//@author @larsborn
//@category malRE
//@keybinding 
//@menupath 
//@toolbar 

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.ArrayList;

import ghidra.app.decompiler.DecompilerLocation;
import ghidra.app.script.GhidraScript;
import ghidra.program.util.EquateOperandFieldLocation;
import ghidra.program.util.OperandFieldLocation;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.EnumDataType;

import java.net.URL;
import java.security.SecureRandom;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;

public class HashDB extends GhidraScript {
	private class HashDBApi {
		private String baseUrl = "https://hashdb.openanalysis.net";

		private class Hashes {
			@SuppressWarnings({ "unused" })
			public long[] hashes;

			public Hashes(long[] hashes) {
				this.hashes = hashes;
			}
		}

		private ArrayList<String> hunt(long[] hashes) throws Exception {
			ArrayList<String> ret = new ArrayList<String>();
			JsonObject response = JsonParser
					.parseString(httpQuery("POST", "hunt", new Gson().toJson(new Hashes(hashes)).getBytes()))
					.getAsJsonObject();
			for (JsonElement hit : response.get("hits").getAsJsonArray()) {
				ret.add(hit.getAsJsonObject().get("algorithm").getAsString());
			}

			return ret;
		}

		public class HashInfo {
			public long hash;
			public String apiName;
			public String permutation;
			public String modules[];

			public HashInfo(long hash, String apiName, String permutation, String modules[]) {
				this.hash = hash;
				this.apiName = apiName;
				this.permutation = permutation;
				this.modules = modules;
			}
		}

		private ArrayList<HashInfo> parseHashInfoFromJson(String httpResponse) {
			JsonObject response = JsonParser.parseString(httpResponse).getAsJsonObject();
			ArrayList<HashInfo> ret = new ArrayList<HashInfo>();
			for (JsonElement hashEntry : response.get("hashes").getAsJsonArray()) {
				JsonObject hashObject = hashEntry.getAsJsonObject();
				JsonObject stringInfo = hashObject.get("string").getAsJsonObject();
				JsonArray modulesArray = stringInfo.get("modules").getAsJsonArray();

				String[] modules = new String[modulesArray.size()];
				for (int i = 0; i < modules.length; i++) {
					modules[i] = modulesArray.get(i).getAsString();
				}
				if (!stringInfo.get("is_api").getAsBoolean()) {
					continue;
				}
				ret.add(new HashInfo(hashObject.get("hash").getAsLong(), stringInfo.get("api").getAsString(),
						stringInfo.get("permutation").getAsString(), modules));
			}
			return ret;
		}

		private ArrayList<HashInfo> resolve(String algorithm, long hash) throws Exception {
			ArrayList<HashInfo> ret = parseHashInfoFromJson(
					httpQuery("GET", String.format("hash/%s/%d", algorithm, hash)));
			for (HashInfo hashInfo : ret) {
				if (hashInfo.hash != hash) {
					throw new Exception("hash mismatch");
				}
			}
			return ret;
		}

		private ArrayList<HashInfo> module(String module, String algorithm, String permutation) throws Exception {
			return parseHashInfoFromJson(
					httpQuery("GET", String.format("module/%s/%s/%s", module, algorithm, permutation)));
		}

		private String httpQuery(String method, String endpoint) throws Exception {
			return httpQuery(method, endpoint, null);
		}

		private String httpQuery(String method, String endpoint, byte[] postData) throws Exception {
			String urlString = String.format("%s/%s", baseUrl, endpoint);
			println(String.format("[HashDB] %s %s", method, urlString));
			URL url = new URL(urlString);
			SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
			sslContext.init(null, null, new SecureRandom());
			HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
			conn.setSSLSocketFactory(sslContext.getSocketFactory());

			conn.setInstanceFollowRedirects(true);
			conn.setDoOutput(true);
			conn.setRequestMethod(method);
			conn.setUseCaches(false);
			if (postData != null) {
				conn.setRequestProperty("Content-Type", "application/json; utf-8");
				conn.setRequestProperty("Content-Length", Integer.toString(postData.length));
				try (OutputStream wr = conn.getOutputStream()) {
					wr.write(postData);
				}
			}

			try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), "utf-8"))) {
				StringBuilder response = new StringBuilder();
				String responseLine = null;
				while ((responseLine = br.readLine()) != null) {
					response.append(responseLine.trim());
				}
				println(String.format("[HashDB] HTTP Response: %s", response));				
				return response.toString();
			}
		}

	}

	public void run() throws Exception {
		HashDBApi api = new HashDBApi();
		long hash;
		try {
			hash = getSelectedHash();
		} catch (Exception e) {
			println(String.format("[HashDB] Move your coursor! %s", e.getMessage()));
			return;
		}
		println(String.format("[HashDB] Querying hash 0x%08x", hash));
		long[] hashes = { hash };
		ArrayList<String> algorithms = api.hunt(hashes);
		if (algorithms.size() == 0) {
			println(String.format("[HashDB] Could not identify any hashing algorithms"));
		}
		else if (algorithms.size() == 1) {
			String algorithm = algorithms.iterator().next();
			ArrayList<HashDB.HashDBApi.HashInfo> resolved = api.resolve(algorithm, hash);
			if (resolved.size() == 0) {
				println("[HashDB] No resolution found");
				return;
			} else if (resolved.size() > 1) {
				println("[HashDB] Hash collision, using first value");
			}
			HashDB.HashDBApi.HashInfo inputHashInfo = resolved.iterator().next();
			if (inputHashInfo.modules.length == 0) {
				println("[HashDB] No module found");
				return;
			}
			DataTypeManager dataTypeManager = getCurrentProgram().getDataTypeManager();
			DataType existingDataType = dataTypeManager.getDataType(new DataTypePath("/HashDB", "ApiHashes"));
			EnumDataType hashEnumeration;
			if (existingDataType == null) {
				hashEnumeration = new EnumDataType(new CategoryPath("/HashDB"), "ApiHashes", 4);
			} else {
				hashEnumeration = (EnumDataType) existingDataType.copy(dataTypeManager);
			}
			int cnt = 0;
			for (String module : inputHashInfo.modules) {
				for (HashDB.HashDBApi.HashInfo hashInfo : api.module(module, algorithm, inputHashInfo.permutation)) {
					try {
						hashEnumeration.add(hashInfo.apiName, hashInfo.hash);
						cnt++;
					} catch (IllegalArgumentException e) {
					}
				}
			}

			dataTypeManager.addDataType(hashEnumeration, DataTypeConflictHandler.REPLACE_HANDLER);
			println(String.format("[HashDB] Added %d enum values to %s! \\o/", cnt, "ApiHashes"));

		} else {
			println("[HashDB] Not implemented yet");
		}
	}

	private long getSelectedHash() throws Exception {
		String s;
		int b = 10;
		if (currentLocation instanceof DecompilerLocation) {
			s = ((DecompilerLocation) currentLocation).getToken().getText();
		} else if (currentLocation instanceof EquateOperandFieldLocation) {
			s = ((EquateOperandFieldLocation) currentLocation).getOperandRepresentation();
		} else if (currentLocation instanceof OperandFieldLocation) {
			s = ((OperandFieldLocation) currentLocation).getOperandRepresentation();
		} else {
			throw new Exception(String.format("[HashDB] Cannot handle selection: %s", currentLocation.toString()));
		}
		if (s.endsWith("h")) {
			s = s.substring(0, s.length() - 1);
			b = 16;
		}
		if (s.startsWith("0x")) {
			s = s.substring(2, s.length());
			b = 16;
		}
		return Long.parseLong(s, b);
	}
}
