package org.owasp.dependencycheck;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.owasp.dependencycheck.analyzer.AnalysisPhase;
import org.owasp.dependencycheck.analyzer.Analyzer;
import org.owasp.dependencycheck.analyzer.CPEAnalyzer;
import org.owasp.dependencycheck.analyzer.NvdCveAnalyzer;
import org.owasp.dependencycheck.analyzer.RubyBundleAuditAnalyzer;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.owasp.dependencycheck.data.update.NvdCveUpdater;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.exception.NoDataException;
import org.owasp.dependencycheck.exception.ReportException;
import org.owasp.dependencycheck.reporting.ReportGenerator;
import org.owasp.dependencycheck.reporting.ReportGenerator.Format;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Pair;
import org.owasp.dependencycheck.utils.Settings;

public class HdivEngine extends Engine {

	private AnalysisPhase endPhase = AnalysisPhase.FINAL;
	private AnalysisPhase startPhase = AnalysisPhase.INITIAL;
	
	public HdivEngine() throws DatabaseException {
		// TODO Auto-generated constructor stub
	}

	public HdivEngine(ClassLoader serviceClassLoader) throws DatabaseException {
		super(serviceClassLoader);
	}
	
    protected void ensureDataExists() throws NoDataException {
    	if(endPhase.compareTo(AnalysisPhase.IDENTIFIER_ANALYSIS)>=0) {
    		super.ensureDataExists();
    	}
    }
    
    @Override
	protected boolean skipPhase(AnalysisPhase phase) {
		return phase.compareTo(startPhase)<0||phase.compareTo(endPhase)>0;
	}
    
    public void doUpdates() throws UpdateException {
    	if(endPhase==AnalysisPhase.FINAL) {
    		super.doUpdates();
    	}
    }

	public static void main(String [] args) throws FileNotFoundException, IOException, Exception {
		System.out.println(System.getProperty("java.version"));
		
		
    	Settings.initialize();

    	
    	HdivEngine engine = new HdivEngine();
    	engine.endPhase = AnalysisPhase.PRE_IDENTIFIER_ANALYSIS;
    	
    	List<Analyzer> removed = new ArrayList<>();
    	
    	for (Iterator<Analyzer> iterator = engine.getAnalyzers().iterator(); iterator.hasNext();) {
			Analyzer analyzer = (Analyzer) iterator.next();
			if(analyzer instanceof CPEAnalyzer || analyzer instanceof NvdCveAnalyzer || analyzer instanceof RubyBundleAuditAnalyzer) {
				removed.add(analyzer);
				iterator.remove();
			}
		}
    	
//    	engine.accept(new File("/dummyPath/dummyFile.jar"));
//    	
//    	Dependency d = new Dependency();
//    	d.setMd5sum(Checksum.getMD5Checksum(new File("/Users/anderruiz/.m2/repository/org/springframework/spring-core/3.0.0.RELEASE/spring-core-3.0.0.RELEASE.jar")));
//    	d.setSha1sum(Checksum.getSHA1Checksum(new File("/Users/anderruiz/.m2/repository/org/springframework/spring-core/3.0.0.RELEASE/spring-core-3.0.0.RELEASE.jar")));
//    	d.setFileName("spring-core-3.0.0.RELEASE.jar");
//    	
//    	String path = "/Users/anderruiz/.m2/repository/org/springframework/spring-core/3.0.0.RELEASE";
//    	
//    	d.setFilePath(path+"/spring-core-3.0.0.RELEASE.jar");
//    	d.setPackagePath(path+"/spring-core-3.0.0.RELEASE.jar");
//    	d.setActualFilePath(path+"/spring-core-3.0.0.RELEASE.jar");
//    	
//    	
//    	JarAnalyzer analyzer = new JarAnalyzer();
//    	analyzer.analyze(d, null);
//    	
//    	path = "/dummyPath";
//    	
//    	d.setFilePath(path+"/spring-core-3.0.0.RELEASE.jar");
//    	d.setPackagePath(path+"/spring-core-3.0.0.RELEASE.jar");
//    	d.setActualFilePath(path+"/spring-core-3.0.0.RELEASE.jar");
//    	engine.setDependencies(java.util.Arrays.asList(d));
    	System.out.println(engine.scan(new File("/Library/Java/JavaVirtualMachines/jdk1.8.0_77.jdk/Contents/Home/jre/lib/rt.jar")));
    	

    	//engine.getDependencies().add(d2);
    	
    	//engine.analyzeDependencies();
    	final List<Dependency> dependencies = new ArrayList<Dependency>(engine.getDependencies());
    	
    	engine.endPhase = AnalysisPhase.FINAL;
    	engine.startPhase = AnalysisPhase.IDENTIFIER_ANALYSIS;
    	engine.getDependencies().clear();
    	//Dependency d = dependencies.get(0);
    	String path = "/dummyPath";
    	System.out.println("Updating");
//    	engine.update();
    	System.out.println("Updated");
    	
//    	d.setFilePath(path+"/spring-core-3.0.0.RELEASE.jar");
//    	d.setPackagePath(path+"/spring-core-3.0.0.RELEASE.jar");
//    	d.setActualFilePath(path+"/spring-core-3.0.0.RELEASE.jar");
    	//dependencies.clear();
    	
    	Dependency d2 = new Dependency();
    	d2.getVendorEvidence().addEvidence("rt", "oracle", "oracle", Confidence.HIGHEST);
    	d2.getProductEvidence().addEvidence("rt", "jdk", "jdk", Confidence.HIGHEST);
    	d2.getVersionEvidence().addEvidence("rt", "version", "1.8.0:update_51", Confidence.HIGHEST );
    	d2.addIdentifier("maven", "oracle:jdk:1.8.0:update_51", "http://hdiv.com");
    	d2.setFileName("rt.jar");
    	d2.setActualFilePath("/dummy/rt.jar");
    	d2.setFilePath("rt.jar");
    	// dependencies.add(d2);
    	
    	d2 = new Dependency();
    	d2.getVendorEvidence().addEvidence("rt", "oracle", "oracle", Confidence.HIGHEST);
    	d2.getProductEvidence().addEvidence("rt", "jrockit", "jrockit", Confidence.HIGHEST);
    	d2.getVersionEvidence().addEvidence("rt", "version", "r28.3.13", Confidence.HIGHEST );
    	d2.addIdentifier("maven", "com.oracle:jrockit:r28.3.13", "http://hdiv.com");
    	d2.setFileName("rt.jar");
    	d2.setActualFilePath("/dummy/rt.jar");
    	d2.setFilePath("rt.jar");
//    	dependencies.add(d2);
    	
    	d2 = new Dependency();
    	d2.getVendorEvidence().addEvidence("rt", "ibm", "ibm", Confidence.HIGHEST);
    	d2.getProductEvidence().addEvidence("rt", "websphere_application_server", "websphere_application_server", Confidence.HIGHEST);
    	d2.getVersionEvidence().addEvidence("rt", "version", "7.0.0.25", Confidence.HIGHEST );
    	d2.addIdentifier("maven", "ibm:websphere_application_server:7.0.0.25", "http://hdiv.com");
    	d2.setFileName("rt.jar");
    	d2.setActualFilePath("/dummy/rt.jar");
    	d2.setFilePath("rt.jar");
    	//dependencies.add(d2);
    	
    	d2 = new Dependency();
    	d2.getVendorEvidence().addEvidence("rt", "redhat", "redhat", Confidence.HIGHEST);
    	d2.getProductEvidence().addEvidence("rt", "jboss_enterprise_application_platform", "jboss_enterprise_application_platform", Confidence.HIGHEST);
    	d2.getVersionEvidence().addEvidence("rt", "version", "4.2.2", Confidence.HIGHEST );
    	d2.addIdentifier("maven", "ibm:websphere_application_server:7.0.0.25", "http://hdiv.com");
    	d2.setFileName("rt.jar");
    	d2.setActualFilePath("/dummy/rt.jar");
    	d2.setFilePath("rt.jar");
    	//dependencies.add(d2);
    	
    	d2 = new Dependency();
    	d2.getVendorEvidence().addEvidence("rt", "oracle", "oracle", Confidence.HIGHEST);
    	d2.getProductEvidence().addEvidence("rt", "jdk", "jdk", Confidence.HIGHEST);
    	d2.getVersionEvidence().addEvidence("rt", "version", "1.7.0:update_40", Confidence.HIGHEST );
    	d2.addIdentifier("maven", "oracle:jdk:1.7.0:update_40", "http://hdiv.com");
    	d2.setFileName("rt.jar");
    	d2.setActualFilePath("/dummy/rt.jar");
    	d2.setFilePath("rt.jar");
    	dependencies.add(d2);
    	
    	engine.setDependencies(dependencies);

    	
    	
    	engine.analyzeDependencies();
    	
    	
    	
for (Dependency dependency : dependencies) {
	consolidateJRE(dependency);
	System.out.println(dependency.toStringEx());
		}
    	
        final CveDB cve = CveDB.getInstance();
//        
//        Set<Pair<String,String>> values = cve.getVendorProductList();
//        for (Pair<String, String> pair : values) {
//			System.out.println(pair.getLeft()+" -> "+pair.getRight());
//		}
        
        
        
        final DatabaseProperties prop = cve.getDatabaseProperties();
        final ReportGenerator report = new ReportGenerator("myapp", engine.getDependencies(), engine.getAnalyzers(), prop);
        try {
            report.write("salida2.html", Format.HTML);
        } catch (ReportException ex) {

                throw ex;
        }
    	
    }
	
	private static void consolidateJRE(Dependency dependency) {
		Set<Evidence> evidence = dependency.getProductEvidence().getEvidence("rt", "jdk");
		if(!evidence.isEmpty()) {
			String version = dependency.getVersionEvidence().getEvidence().iterator().next().getValue();
			String update = null;
			if(version.indexOf(':')!=-1) {
				update = version.substring(version.indexOf(':')+1);
				version = version.substring(0, version.indexOf(':'));
			}
			Set<Vulnerability> vulnerabilities = dependency.getVulnerabilities();
			for (Iterator<Vulnerability> iterator = vulnerabilities.iterator(); iterator.hasNext();) {
				boolean ok = false;
				Vulnerability vulnerability = (Vulnerability) iterator.next();
				for(VulnerableSoftware vs : vulnerability.getVulnerableSoftware()) {
					if(version.equals(vs.getVersion())) {
						System.out.println("Version:"+vs.getVersion()+" "+vs.getUpdate()+" and update:"+update);
						if(vs.getUpdate()==null && update==null) {
							ok = true;
							break;
						}
						else if(update!=null && update.equals(vs.getUpdate())) {
							ok = true;
							break;
						}
					}
				}
				if(!ok) {
					iterator.remove();
				}
			}
		}
	}
	
	public void setOfflineMode(boolean offline) {
		Settings.setBoolean(Settings.KEYS.UPDATE_NVDCVE_ENABLED, !offline);
	}
	
	public void update() throws UpdateException, InvalidSettingException, DatabaseException {
		CveDB.getInstance().cleanupDatabase();
		NvdCveUpdater update = new NvdCveUpdater();
		
		final int startYear = Settings.getInt(Settings.KEYS.CVE_START_YEAR, 2002);
        final int endYear = Calendar.getInstance().get(Calendar.YEAR);
        boolean needsFullUpdate = false;
        for (int y = startYear; y <= endYear; y++) {
        	CveDB.getInstance().getDatabaseProperties().save(DatabaseProperties.LAST_UPDATED_BASE + y, "0");
        }
		
		int previousDays = Settings.getInt(Settings.KEYS.CVE_MODIFIED_VALID_FOR_DAYS, 7);
		int previous = Settings.getInt(Settings.KEYS.CVE_CHECK_VALID_FOR_HOURS);
		Settings.setInt(Settings.KEYS.CVE_CHECK_VALID_FOR_HOURS, -1);
		Settings.setInt(Settings.KEYS.CVE_MODIFIED_VALID_FOR_DAYS, -1);
		update.update();
		Settings.setInt(Settings.KEYS.CVE_CHECK_VALID_FOR_HOURS, previous);
		Settings.setInt(Settings.KEYS.CVE_MODIFIED_VALID_FOR_DAYS, previousDays);
	}
}
