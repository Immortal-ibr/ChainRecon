# Base class for report plugins
class ReportPlugin:
    def generate(self, analysis_data, output_path):
        """
        Generate a report from analysis_data and save to output_path.
        Must be implemented by plugin subclasses.
        """
        raise NotImplementedError
