//Script to look up API functions in HashDB (https://hashdb.openanalysis.net/)
//@author @larsborn
//@category malRE
//@keybinding 
//@menupath 
//@toolbar 

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;

import ghidra.app.decompiler.DecompilerLocation;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin;
import ghidra.app.plugin.core.instructionsearch.ui.InstructionSearchDialog;
import ghidra.app.plugin.core.instructionsearch.util.InstructionSearchUtils;
import ghidra.app.plugin.core.string.StringTablePlugin;
import ghidra.app.script.GhidraScript;
import ghidra.app.tablechooser.AddressableRowObject;
import ghidra.app.tablechooser.ColumnDisplay;
import ghidra.app.tablechooser.StringColumnDisplay;
import ghidra.app.tablechooser.TableChooserDialog;
import ghidra.app.tablechooser.TableChooserExecutor;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.util.AddressFieldLocation;
import ghidra.program.util.EquateOperandFieldLocation;
import ghidra.program.util.OperandFieldLocation;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import docking.widgets.DropDownTextField;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GDLabel;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;

import java.net.URL;
import java.security.SecureRandom;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTextField;

public class HashDB extends GhidraScript {
	boolean HTTP_DEBUGGING = false;

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
			if (HTTP_DEBUGGING) {
				println(String.format("[HashDB] %s %s", method, urlString));
			}
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
				if (HTTP_DEBUGGING) {
					println(String.format("[HashDB] HTTP Response: %s", response));
				}
				return response.toString();
			}
		}
	}

	private class HashTableExecutor implements TableChooserExecutor {
		public HashTableExecutor() {

		}

		@Override
		public String getButtonName() {
			return "Query!";
		}

		@Override
		public boolean execute(AddressableRowObject rowObject) {
			return false;
		}

	}

	class HashTable extends TableChooserDialog {
		private JTextField enumNameTextField;
		private JTextField transformationTextField;
		private GCheckBox resolveModulesCheckbox;

		public HashTable(PluginTool tool, TableChooserExecutor executor, Program program, String title) {
			super(tool, executor, program, title, null, false);
		}

		public String getTransformation() {
			return transformationTextField.getText();
		}

		public String getEnumName() {
			return enumNameTextField.getText();
		}

		public boolean resolveEntireModules() {
			return resolveModulesCheckbox.isSelected();
		}

		protected void addWorkPanel(JComponent hauptPanele) {
			int rowCount = 3;
			super.addWorkPanel(hauptPanele);

			JPanel columnPanel = new JPanel(new BorderLayout(10, 10));
			JPanel leftPanel = new JPanel(new GridLayout(rowCount, 1));
			JPanel rightPanel = new JPanel(new GridLayout(rowCount, 1));
			columnPanel.add(leftPanel, BorderLayout.WEST);
			columnPanel.add(rightPanel, BorderLayout.CENTER);

			leftPanel.add(new GDLabel("Enum Name:"));
			enumNameTextField = new JTextField("HashDBEnum");
			rightPanel.add(enumNameTextField);

			leftPanel.add(new GDLabel("Hash Transformation:"));
			transformationTextField = new JTextField("(((X ^ 0x76c7) << 0x10 ^ X) ^ 0xafb9) & 0x1fffff");
			rightPanel.add(transformationTextField);

			leftPanel.add(new GDLabel(""));
			resolveModulesCheckbox = new GCheckBox("Resolve Entire Modules");
			rightPanel.add(resolveModulesCheckbox);

			JPanel outerPanel = new JPanel(new BorderLayout());
			outerPanel.add(columnPanel, BorderLayout.NORTH);

			JButton queryAllButton = new JButton("Query All");
			outerPanel.add(queryAllButton, BorderLayout.SOUTH);
			queryAllButton.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					resolveHashes();
				}
			});
			hauptPanele.add(outerPanel, BorderLayout.SOUTH);
		}
	}

	static HashTable dialog = null;
	static HashMap<Long, HashLocation> selectedHashes = null;

	private void showDialog() {
		boolean newDialog = dialog == null || !dialog.isVisible();
		if (newDialog || selectedHashes == null) {
			println("[HashDB] Creating new hash map.");
			selectedHashes = new HashMap<Long, HashLocation>();
		}
		if (newDialog) {
			println("[HashDB] Creating new dialog.");
			dialog = new HashTable(state.getTool(), new HashTableExecutor(), currentProgram, "HashDB is BestDB");
			configureTableColumns(dialog);
		}

		state.getTool().showDialog(dialog);
	}

	private boolean addHash(long hash) {
		HashLocation newRow = new HashLocation(currentAddress, hash);
		if (selectedHashes.containsKey(hash)) {
			return false;
		}
		selectedHashes.put(hash, newRow);
		dialog.add(newRow);
		return true;
	}

	public void run() throws Exception {
		boolean autoResolveNewHashes = false;
		long hash;
		try {
			hash = getSelectedHash();
		} catch (Exception e) {
			println(String.format("[HashDB] Error: %s", e.getMessage()));
			return;
		}
		showDialog();
		if (addHash(hash) && autoResolveNewHashes) {
			println(String.format("[HashDB] Querying hash 0x%08x", hash));
			long[] hashes = { hash };
			resolveHashes(hashes);
		}
	}

	private void onHashResolution(EnumDataType hashEnumeration, HashDB.HashDBApi.HashInfo hashInfo) {
		hashEnumeration.add(hashInfo.apiName, hashInfo.hash);
		if (selectedHashes.containsKey(hashInfo.hash)) {
			HashLocation existingRow = selectedHashes.get(hashInfo.hash);
			existingRow.resolution = hashInfo.apiName;
			refreshTable();
		}
	}
	
	private void resolveHashes(long[] hashes) throws Exception {
		HashDBApi api = new HashDBApi();
		ArrayList<String> algorithms = api.hunt(hashes);
		if (algorithms.size() == 0) {
			println(String.format("[HashDB] Could not identify any hashing algorithms"));
		} else if (algorithms.size() == 1) {
			int resolveCount = 0;

			String hashEnumName = dialog.getEnumName(); 
			DataTypeManager dataTypeManager = getCurrentProgram().getDataTypeManager();
			DataType existingDataType = dataTypeManager.getDataType(new DataTypePath("/HashDB", dialog.getEnumName()));
			EnumDataType hashEnumeration = null;
			
			if (existingDataType == null) {
				hashEnumeration = new EnumDataType(new CategoryPath("/HashDB"), hashEnumName, 4);
			} else {
				hashEnumeration = (EnumDataType) existingDataType.copy(dataTypeManager);
			}

			String algorithm = algorithms.iterator().next();

			for (long hash : hashes) {
				ArrayList<HashDB.HashDBApi.HashInfo> resolved = api.resolve(algorithm, hash);
				if (resolved.size() == 0) {
					println("[HashDB] No resolution found");
					return;
				} else if (resolved.size() > 1) {
					println("[HashDB] Hash collision, using first value");
				}
				HashDB.HashDBApi.HashInfo inputHashInfo = resolved.iterator().next();
				if (inputHashInfo.modules.length == 0) {
					println(String.format("[HashDB] No module found for hash 0x%x", hash));
					return;
				}
				if (dialog.resolveEntireModules()) {
					for (String module : inputHashInfo.modules) {
						for (HashDB.HashDBApi.HashInfo hashInfo : api.module(module, algorithm, inputHashInfo.permutation)) {
							onHashResolution(hashEnumeration, hashInfo);
							resolveCount++;
						}
					}
				} else {
					onHashResolution(hashEnumeration, inputHashInfo);
					resolveCount++;
				}
			}
			int id = currentProgram.startTransaction(String.format("updating enumeration %s", hashEnumName));
			dataTypeManager.addDataType(hashEnumeration, DataTypeConflictHandler.REPLACE_HANDLER);
			currentProgram.endTransaction(id, true);
			println(String.format("[HashDB] Added %d enum values to %s! \\o/", resolveCount, dialog.getEnumName()));
		} else {
			println("[HashDB] More than 1 algorithm found, not implemented yet");
		}
	}

	private void resolveHashes() {
		List<Long> toQuery = new ArrayList<Long>();
		for (HashLocation hashLocation : selectedHashes.values()) {
			if (hashLocation.resolution == null) {
				toQuery.add(hashLocation.hashValue);
			}
		}
		try {
			resolveHashes(toQuery.stream().mapToLong(l -> l).toArray());
		} catch (Exception e) {
			println(String.format("[HashDB] exception during resolution: %s\n", e.toString()));
		}

	}

	private void refreshTable() {
		// TODO this is just a hack, find out the proper way to notify the dialog of
		// changes in the underlying data
		for (int i = 0; i < dialog.getRowCount(); i++) {
			dialog.selectRows(i);
			dialog.clearSelection();
		}
	}

	private long transformHash(long hash, String transformation) throws ScriptException {
		ScriptEngineManager manager = new ScriptEngineManager();
		manager.put("X", hash);
		ScriptEngine engine = manager.getEngineByName("js");
		return (long) engine.eval(transformation);
	}

	private void configureTableColumns(TableChooserDialog dialog) {
		StringColumnDisplay hashColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Hash";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				HashLocation row = (HashLocation) rowObject;
				return row.getHashValue();
			}

			@Override
			public int compare(AddressableRowObject o1, AddressableRowObject o2) {
				return getColumnValue(o1).compareTo(getColumnValue(o2));
			}
		};

		dialog.addCustomColumn(hashColumn);
		StringColumnDisplay resolutionColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Resolution";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				HashLocation row = (HashLocation) rowObject;
				return row.getResolution() == null ? "-" : row.getResolution();
			}

			@Override
			public int compare(AddressableRowObject o1, AddressableRowObject o2) {
				return getColumnValue(o1).compareTo(getColumnValue(o2));
			}
		};

		dialog.addCustomColumn(resolutionColumn);
	}

	class HashLocation implements AddressableRowObject {
		private Address address;
		private long hashValue;
		private String resolution;

		HashLocation(Address address, long hashValue) {
			this.address = address;
			this.hashValue = hashValue;
			this.resolution = null;
		}

		@Override
		public Address getAddress() {
			return address;
		}

		public String getHashValue() {
			return String.format("%08x", hashValue);
		}

		public String getResolution() {
			return this.resolution;
		}
	}

	private long getSelectedHash() throws Exception {
		// First try to read the value of defined or undefined data. This covers many
		// different types of locations where the cursor could be in the data view.
		Data data = currentProgram.getListing().getDataAt(currentLocation.getAddress());
		if (data != null)
			return data.getBigInteger(0, data.getDataType().getLength(), false).longValue();
		if (currentLocation instanceof DecompilerLocation) {
			Varnode varNode = ((DecompilerLocation) currentLocation).getToken().getVarnode();
			if (varNode == null || !varNode.isConstant())
				throw new Exception("You have to select a constant.");
			return varNode.getOffset();
		} else if (currentLocation instanceof OperandFieldLocation) {
			OperandFieldLocation opLoc = (OperandFieldLocation) currentLocation;
			Address opAddress = opLoc.getAddress();
			Instruction instruction = currentProgram.getListing().getInstructionAt(opAddress);
			if (instruction == null)
				throw new Exception("Operand selected, but no instruction or data found.");
			Object[] args = instruction.getOpObjects(opLoc.getOperandIndex());
			int index = opLoc.getSubOperandIndex();
			if (index < args.length && args[index] instanceof Scalar)
				return ((Scalar) args[index]).getUnsignedValue();
			throw new Exception("The selection is not a scalar value.");
		} else {
			throw new Exception(String.format("Don't know how to handle program location of type %s",
					currentLocation.getClass().getSimpleName()));
		}
	}
}
